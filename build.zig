const std = @import("std");

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

    const kdbx_module = b.addModule("kdbx", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    kdbx_module.addImport("dishwasher", dishwasher_module);
    kdbx_module.addImport("uuid", uuid_module);
    try b.modules.put(b.dupe("kdbx"), kdbx_module);

    const kdbx_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    kdbx_unit_tests.root_module.addImport("dishwasher", dishwasher_module);
    kdbx_unit_tests.root_module.addImport("uuid", uuid_module);
    const run_kdbx_unit_tests = b.addRunArtifact(kdbx_unit_tests);

    const test_step = b.step("test", "Run unit tests");

    test_step.dependOn(&run_kdbx_unit_tests.step);

    const exe = b.addExecutable(.{
        .name = "passkeez",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("kdbx", kdbx_module);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
