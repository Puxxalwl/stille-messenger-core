//! Сборка ядра: библиотека stille-messenger, CLI-демон, тесты по группам.
//! Тестовые корни живут в tests/ (тела тестов — не в src/); ко-located
//! инвариантные тесты файлов собираются тест-режимом самих модулей:
//! test-unit — библиотека (корень src/stille-messenger.zig),
//! test-app — дерево демона (корень main.zig) + tests/app.zig,
//! test-integration — tests/integration.zig. Шаг test запускает всё.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("stille-messenger", .{
        .root_source_file = b.path("src/stille-messenger.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Дерево демона: отдельный модуль (один и для CLI, и для тестов).
    const app_mod = b.createModule(.{
        .root_source_file = b.path("src/stille-messenger/app/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    app_mod.addImport("stille-messenger", mod);

    const exe = b.addExecutable(.{
        .name = "stille-messenger-core",
        .root_module = app_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the CLI");
    run_step.dependOn(&run_cmd.step);

    // ---- unit: библиотека (ко-located тесты всех файлов модуля) ----
    const unit = b.addTest(.{ .root_module = mod });
    const run_unit = b.addRunArtifact(unit);
    const unit_step = b.step("test-unit", "Run library module tests");
    unit_step.dependOn(&run_unit.step);

    // ---- app: ко-located тесты дерева демона + тела тестов в tests/ ----
    const app_internal = b.addTest(.{ .root_module = app_mod });
    const run_app_internal = b.addRunArtifact(app_internal);

    const daemon_mod = b.createModule(.{
        .root_source_file = b.path("tests/app.zig"),
        .target = target,
        .optimize = optimize,
    });
    daemon_mod.addImport("stille-messenger", mod);
    daemon_mod.addImport("app-main", app_mod);
    const daemon_tests = b.addTest(.{ .root_module = daemon_mod });
    const run_daemon = b.addRunArtifact(daemon_tests);
    const app_step = b.step("test-app", "Run daemon (app layer) tests");
    app_step.dependOn(&run_app_internal.step);
    app_step.dependOn(&run_daemon.step);

    // ---- proto: конформанс протокола конвертов (tests/proto/) ----
    const proto_mod = b.createModule(.{
        .root_source_file = b.path("tests/proto.zig"),
        .target = target,
        .optimize = optimize,
    });
    proto_mod.addImport("stille-messenger", mod);
    const proto_tests = b.addTest(.{ .root_module = proto_mod });
    const run_proto = b.addRunArtifact(proto_tests);
    const proto_step = b.step("test-proto", "Run protocol conformance tests");
    proto_step.dependOn(&run_proto.step);

    // ---- crypto: модульные тесты криптомодулей (tests/crypto/) ----
    const crypto_mod = b.createModule(.{
        .root_source_file = b.path("tests/crypto.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_mod.addImport("stille-messenger", mod);
    const crypto_tests = b.addTest(.{ .root_module = crypto_mod });
    const run_crypto = b.addRunArtifact(crypto_tests);
    const crypto_step = b.step("test-crypto", "Run crypto module tests");
    crypto_step.dependOn(&run_crypto.step);

    // ---- integration: сквозные сценарии поверх библиотеки ----
    const integ_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("stille-messenger", mod);
    const integ = b.addTest(.{ .root_module = integ_mod });
    const run_integ = b.addRunArtifact(integ);
    const integ_step = b.step("test-integration", "Run integration tests");
    integ_step.dependOn(&run_integ.step);

    // ---- всё вместе (make test) ----
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(&run_app_internal.step);
    test_step.dependOn(&run_daemon.step);
    test_step.dependOn(&run_proto.step);
    test_step.dependOn(&run_crypto.step);
    test_step.dependOn(&run_integ.step);

    // ---- bench: транспорт (прямой TCP vs relay vs punch), OReleaseFast ----
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("tests/bench_transport.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("stille-messenger", mod);
    const bench_exe = b.addExecutable(.{
        .name = "bench-transport",
        .root_module = bench_mod,
    });
    const bench_cmd = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run transport benchmark");
    bench_step.dependOn(&bench_cmd.step);
}
