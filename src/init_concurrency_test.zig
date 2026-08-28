const std = @import("std");
const initialization = @import("init.zig");
const c = @import("c.zig").raw;

const worker_count = 16;

const Barrier = struct {
    ready: usize = 0,
    start: bool = false,

    fn wait(self: *Barrier) void {
        _ = @atomicRmw(usize, &self.ready, .Add, 1, .acq_rel);
        while (!@atomicLoad(bool, &self.start, .acquire)) {
            std.Thread.yield() catch {};
        }
    }
};

const Worker = struct {
    fn run(barrier: *Barrier, failed: *bool) void {
        barrier.wait();
        initialization.ensureInitialized() catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        var digest: [32]u8 = undefined;
        c.SymCryptSha256(null, 0, &digest);
    }
};

fn waitFor(comptime predicate: fn () bool) !void {
    const start = std.Io.Clock.awake.now(std.testing.io);
    while (!predicate()) {
        const elapsed = start.durationTo(std.Io.Clock.awake.now(std.testing.io));
        if (elapsed.toSeconds() >= 10) return error.TestUnexpectedResult;
        std.Thread.yield() catch {};
    }
}

test "first initialization makes every contender wait for the CAS winner" {
    initialization.TestHooks.prepare();

    var barrier = Barrier{};
    var failed = false;
    var threads: [worker_count]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &barrier, &failed });
    }
    var joined = false;
    defer if (!joined) {
        initialization.TestHooks.releaseClaim();
        for (&threads) |*thread| thread.join();
    };

    while (@atomicLoad(usize, &barrier.ready, .acquire) != worker_count) {
        std.Thread.yield() catch {};
    }
    @atomicStore(bool, &barrier.start, true, .release);

    try waitFor(initialization.TestHooks.claimed);
    try waitFor(struct {
        fn complete() bool {
            return initialization.TestHooks.waiterCount() == worker_count - 1;
        }
    }.complete);

    initialization.TestHooks.releaseClaim();
    for (&threads) |*thread| thread.join();
    joined = true;
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}
