const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("stille-messenger", .{
        .root_source_file = b.path("src/stille-messenger.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "stille-messenger",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/stille-messenger/app/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("stille-messenger", mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the CLI");
    run_step.dependOn(&run_cmd.step);

    const unit_mod = b.createModule(.{
        .root_source_file = b.path("src/stille_messenger_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit = b.addTest(.{ .root_module = unit_mod });
    const run_unit = b.addRunArtifact(unit);
    const test_step = b.step("test", "Run module tests");
    test_step.dependOn(&run_unit.step);

    const integ_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("stille-messenger", mod);
    const integ = b.addTest(.{ .root_module = integ_mod });
    const run_integ = b.addRunArtifact(integ);
    test_step.dependOn(&run_integ.step);

    const app_test_mod = b.createModule(.{
        .root_source_file = b.path("src/stille-messenger/app/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    app_test_mod.addImport("stille-messenger", mod);
    const app_tests = b.addTest(.{ .root_module = app_test_mod });
    const run_app_tests = b.addRunArtifact(app_tests);
    test_step.dependOn(&run_app_tests.step);
}
