/*
 * stateful_proto — a line protocol with four planted bugs behind its state
 * machine.
 *
 * The stateful counterpart to chunked_format: where that one hides its bugs
 * behind checksums that only structured mutation can satisfy, this one hides
 * them behind a *sequence* that only a fuzzer reasoning about protocol state
 * can reach. A mutator that sends one message at a time finds bug 1 and
 * nothing else, however long it runs.
 *
 * Protocol, line-oriented so that both line framing and status-code state
 * labelling apply:
 *
 *   HELLO <version>      220 ready <n>       must be first
 *   AUTH <token>         235 authenticated   needs HELLO; token is LETMEIN
 *                        535 denied
 *   SET <key> <value>    250 stored          needs AUTH
 *   GET <key>            210 <value> / 404 missing
 *   BULK <n>             354 send            next n lines are data
 *   RESET                200 reset
 *   QUIT                 221 bye
 *   anything else        500 unknown / 503 out of order
 *
 * XFUZZ-BUGS: 4
 */

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void bug(int n) {
    /* An unambiguous fault. See testdata/targets/README.md for why these are
     * explicit rather than left for a sanitizer to notice. */
    fprintf(stderr, "XFUZZ-BUG-%d\n", n);
    fflush(stderr);
    abort();
}

/* --- the connection's state ------------------------------------------------
 *
 * This is what makes the target stateful in the way ASR-0002 means: the reply
 * to a message is a function of every message before it, so a session is the
 * unit of work and no amount of single-message fuzzing substitutes for it.
 */
enum phase { PH_NEW, PH_GREETED, PH_AUTHED, PH_BULK };

#define MAX_KEYS 8
#define KEY_LEN 24
#define VAL_LEN 32
#define BULK_SLOTS 2
#define BULK_LINE 32

struct store {
    char key[MAX_KEYS][KEY_LEN];
    char val[MAX_KEYS][VAL_LEN];
    int count;
};

struct conn {
    enum phase phase;
    int sessions;
    int bulk_remaining;

    /* bulk_received counts the lines this connection has accepted across every
     * transfer, and BULK deliberately does not reset it. Bug 3 lives in that
     * word. */
    int bulk_received;
    char bulk[BULK_SLOTS][BULK_LINE];

    struct store *store; /* bug 4 lives in this pointer's lifetime */
};

static void say(FILE *out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fflush(out);
}

/* --- the commands ---------------------------------------------------------- */

static void do_hello(FILE *out, struct conn *c, const char *arg) {
    /* Bug 1: shallow, and reachable from the first message of any session.
     *
     * It is here to be the control: a campaign that cannot find this one has
     * something broken upstream of state entirely — the connection, the
     * framing, the mutation of message zero. Finding it says the session tier
     * works, and nothing at all about state guidance. */
    char version[16];
    size_t n = strlen(arg);
    if (n >= sizeof(version)) bug(1);
    memcpy(version, arg, n);
    version[n] = '\0';

    c->phase = PH_GREETED;
    c->sessions++;
    say(out, "220 ready %d %s\r\n", c->sessions, version);
}

static void do_auth(FILE *out, struct conn *c, const char *arg) {
    if (c->phase == PH_NEW) {
        say(out, "503 hello first\r\n");
        return;
    }
    if (strcmp(arg, "LETMEIN") != 0) {
        say(out, "535 denied\r\n");
        return;
    }
    c->phase = PH_AUTHED;
    if (!c->store) {
        c->store = calloc(1, sizeof(*c->store));
        if (!c->store) exit(1);
    }
    say(out, "235 authenticated\r\n");
}

static void do_set(FILE *out, struct conn *c, char *arg) {
    if (c->phase != PH_AUTHED) {
        say(out, "503 authenticate first\r\n");
        return;
    }
    char *sp = strchr(arg, ' ');
    if (!sp) {
        say(out, "501 need a key and a value\r\n");
        return;
    }
    *sp = '\0';
    const char *key = arg, *val = sp + 1;

    /* Bug 2: the key is bounds-checked and the value is not.
     *
     * This is the exit criterion's bug: reachable only after HELLO and a
     * correct AUTH, so a fuzzer that never assembles a valid two-step
     * handshake cannot reach it however many SET messages it sends. The
     * handshake is the funnel, and getting through it is what state guidance
     * is for. */
    if (strlen(key) >= KEY_LEN) {
        say(out, "501 key too long\r\n");
        return;
    }
    if (c->store->count >= MAX_KEYS) {
        say(out, "452 full\r\n");
        return;
    }
    int i = c->store->count++;
    strcpy(c->store->key[i], key);
    if (strlen(val) >= VAL_LEN) bug(2);
    strcpy(c->store->val[i], val);
    say(out, "250 stored\r\n");
}

static void do_get(FILE *out, struct conn *c, const char *arg) {
    if (c->phase != PH_AUTHED) {
        say(out, "503 authenticate first\r\n");
        return;
    }
    /* Bug 4: a use-after-free reachable only through a *transition* nobody
     * plans for — authenticate, reset, then read.
     *
     * RESET frees the store and leaves the connection authenticated, so this
     * dereferences a pointer to freed memory. It needs the three-step order
     * and no other: auth-then-get is fine, reset-then-get is refused for want
     * of authentication, and auth-reset-auth-get reallocates. This is the bug
     * in the state *pair* rather than in the state, which is why transitions
     * are counted separately from states. */
    if (!c->store) bug(4);

    for (int i = 0; i < c->store->count; i++) {
        if (strcmp(c->store->key[i], arg) == 0) {
            say(out, "210 %s\r\n", c->store->val[i]);
            return;
        }
    }
    say(out, "404 missing\r\n");
}

static void do_bulk(FILE *out, struct conn *c, const char *arg) {
    if (c->phase != PH_AUTHED) {
        say(out, "503 authenticate first\r\n");
        return;
    }
    int n = atoi(arg);
    if (n < 1 || n > 64) {
        say(out, "501 out of range\r\n");
        return;
    }
    /* bulk_received is not reset. A second transfer on the same connection
     * continues where the first left off, which is the whole of bug 3. */
    c->bulk_remaining = n;
    c->phase = PH_BULK;
    say(out, "354 send\r\n");
}

static void do_bulk_line(FILE *out, struct conn *c, const char *line) {
    /* Bug 3: the line counter is per connection and the slot array is not.
     *
     * BULK sets how many lines this transfer expects but does not reset how
     * many the connection has already taken, so a second transfer writes past
     * the end of the array. It needs BULK, its data, and then BULK again —
     * three commands in one order, the third only reachable because the first
     * completed. A campaign that never sends two transfers on one connection
     * cannot find it, however many single transfers it sends. */
    if (strcmp(line, ".") == 0) {
        c->phase = PH_AUTHED;
        say(out, "250 transfer complete\r\n");
        return;
    }
    if (c->bulk_received >= BULK_SLOTS) bug(3);

    size_t n = strlen(line);
    if (n >= BULK_LINE) n = BULK_LINE - 1;
    memcpy(c->bulk[c->bulk_received], line, n);
    c->bulk[c->bulk_received][n] = '\0';
    c->bulk_received++;

    if (--c->bulk_remaining <= 0) {
        c->phase = PH_AUTHED;
        say(out, "250 transfer complete\r\n");
        return;
    }
    say(out, "354 more\r\n");
}

static void do_reset(FILE *out, struct conn *c) {
    if (c->phase == PH_NEW) {
        say(out, "503 hello first\r\n");
        return;
    }
    /* The store goes; the authentication stays. That mismatch is bug 4: every
     * command still believes the connection is authenticated, and one of them
     * reads through a pointer that is no longer there.
     *
     * Cleared rather than left dangling, so the fault is a deterministic null
     * dereference the target reports itself rather than whatever the allocator
     * happens to leave behind — a use-after-free would make the test a
     * measurement of the allocator instead of of the fuzzer (see README). */
    free(c->store);
    c->store = NULL;
    c->bulk_remaining = 0;
    c->bulk_received = 0;
    say(out, "200 reset\r\n");
}

/* --- the session loop ------------------------------------------------------ */

static void serve(int fd) {
    FILE *in = fdopen(fd, "r");
    FILE *out = fdopen(dup(fd), "w");
    if (!in || !out) return;

    struct conn c;
    memset(&c, 0, sizeof(c));

    char line[512];
    while (fgets(line, sizeof(line), in)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';

        if (c.phase == PH_BULK) {
            do_bulk_line(out, &c, line);
            continue;
        }

        char *arg = strchr(line, ' ');
        if (arg) *arg++ = '\0';
        else arg = line + n;

        if (strcmp(line, "HELLO") == 0) do_hello(out, &c, arg);
        else if (strcmp(line, "AUTH") == 0) do_auth(out, &c, arg);
        else if (strcmp(line, "SET") == 0) do_set(out, &c, arg);
        else if (strcmp(line, "GET") == 0) do_get(out, &c, arg);
        else if (strcmp(line, "BULK") == 0) do_bulk(out, &c, arg);
        else if (strcmp(line, "RESET") == 0) do_reset(out, &c);
        else if (strcmp(line, "QUIT") == 0) { say(out, "221 bye\r\n"); break; }
        else if (c.phase == PH_NEW) say(out, "503 hello first\r\n");
        else say(out, "500 unknown\r\n");
    }

    free(c.store);
    fclose(in);
    fclose(out);
}

/* --- listening ------------------------------------------------------------- */

static int listen_unix(const char *path) {
    struct sockaddr_un sa;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "stateful_proto: socket path too long: %s\n", path);
        return -1;
    }
    unlink(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

static int listen_tcp(const char *hostport) {
    const char *colon = strrchr(hostport, ':');
    int port = colon ? atoi(colon + 1) : atoi(hostport);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

static void usage(void) {
    fprintf(stderr,
            "usage: stateful_proto --listen unix:PATH\n"
            "       stateful_proto --listen tcp:127.0.0.1:PORT\n"
            "\n"
            "A line protocol with four planted bugs behind its state machine.\n"
            "Serves connections one at a time, forever.\n");
}

int main(int argc, char **argv) {
    const char *listen_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) listen_arg = argv[++i];
        else { usage(); return 2; }
    }
    if (!listen_arg) { usage(); return 2; }

    /* A client that hangs up mid-reply would otherwise kill the server with
     * SIGPIPE, and the fuzzer would report every disconnect as a crash. */
    signal(SIGPIPE, SIG_IGN);

    int fd;
    if (strncmp(listen_arg, "unix:", 5) == 0) fd = listen_unix(listen_arg + 5);
    else if (strncmp(listen_arg, "tcp:", 4) == 0) fd = listen_tcp(listen_arg + 4);
    else { usage(); return 2; }

    if (fd < 0) {
        fprintf(stderr, "stateful_proto: cannot listen on %s: %s\n", listen_arg, strerror(errno));
        return 1;
    }

    /* One connection at a time, in this process. Serving concurrently would
     * make a crash unattributable to the session that caused it, which is the
     * one thing a fuzzer's target must never do. */
    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        serve(c);
        close(c);
    }
}
