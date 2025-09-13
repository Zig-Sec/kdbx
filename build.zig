const std = @import("std");

//const zigclonedx = @import("zigclonedx");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const uuid_dep = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });
    const uuid_module = uuid_dep.module("uuid");

    const dishwasher_dep = b.dependency("dishwasher", .{
        .target = target,
        .optimize = optimize,
    });
    const dishwasher_module = dishwasher_dep.module("dishwasher");

    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });
    const clap_module = clap_dep.module("clap");

    const kdbx_module = b.addModule("kdbx", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "dishwasher", .module = dishwasher_module },
            .{ .name = "uuid", .module = uuid_module },
        },
    });
    try b.modules.put(b.dupe("kdbx"), kdbx_module);

    const kdbx_unit_tests = b.addTest(.{
        .root_module = kdbx_module,
    });
    const run_kdbx_unit_tests = b.addRunArtifact(kdbx_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_kdbx_unit_tests.step);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "kdbx", .module = kdbx_module },
            .{ .name = "clap", .module = clap_module },
        },
    });

    const exe = b.addExecutable(.{
        .name = "kdbx-cli",
        .root_module = exe_mod,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const gzip_module = b.addModule("gzip", .{
        .root_source_file = b.path("src/gzip.zig"),
        .target = target,
        .optimize = optimize,
    });
    try b.modules.put(b.dupe("gzip"), gzip_module);

    const gzip_unit_tests = b.addTest(.{
        .root_module = gzip_module,
    });
    const run_gzip_unit_tests = b.addRunArtifact(gzip_unit_tests);
    const gzip_test_step = b.step("test-gzip", "Run gzip unit tests");
    gzip_test_step.dependOn(&run_gzip_unit_tests.step);
}
