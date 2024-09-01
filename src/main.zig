const std = @import("std");
const yazap = @import("yazap");
const schnorr = @import("schnorr.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;

const App = yazap.App;
const Arg = yazap.Arg;

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var app = App.init(allocator, "schnorr", "Schnorr Signing (over Ed25519) CLI tool");
    defer app.deinit();

    var cli = app.rootCommand();

    const sign_cmd = app.createCommand("sign", "Sign a message given a private key");
    try sign_cmd.addArg(Arg.singleValueOption("priv", null, "Private key for signing"));
    try sign_cmd.addArg(Arg.singleValueOption("message", 'm', "Message to sign"));

    const verify_cmd = app.createCommand("verify", "Verify a signature given the signer's public key");
    try verify_cmd.addArg(Arg.singleValueOption("pub", null, "Signer's public key"));
    try verify_cmd.addArg(Arg.singleValueOption("message", 'm', "Message used to generate signature"));
    try verify_cmd.addArg(Arg.singleValueOption("signature", 'm', "Signature to verify"));

    try cli.addSubcommand(sign_cmd);
    try cli.addSubcommand(verify_cmd);

    const matches = try app.parseProcess();

    // `Sign` subcommand setup
    if (matches.subcommandMatches("sign")) |sign_cmd_matches| {
        if (sign_cmd_matches.getSingleValue("priv") == null) {
            try stdout.print("Please provide private key for signing", .{});
            try bw.flush();
            return;
        }
        if (sign_cmd_matches.getSingleValue("message") == null) {
            try stdout.print("Please provide message to sign", .{});
            try bw.flush();
            return;
        }

        // const priv = sign_cmd_matches.getSingleValue("priv").?;
        // const pub = Ristretto255.basePoint.mul()

        _ = sign_cmd_matches.getSingleValue("message").?;
        // const _ = try schnorr.Signature.sign(message, priv, allocator);

        try bw.flush();
    }

    // `Verify` subcommand setup
    if (matches.subcommandMatches("verify")) |verify_cmd_matches| {
        if (verify_cmd_matches.getSingleValue("pub") == null) {
            try stdout.print("Please provide signer's public key", .{});
            try bw.flush();
            return;
        }
        if (verify_cmd_matches.getSingleValue("message") == null) {
            try stdout.print("Please provide message to sign", .{});
            try bw.flush();
            return;
        }
        if (verify_cmd_matches.getSingleValue("signature") == null) {
            try stdout.print("Please provide signature to verify", .{});
            try bw.flush();
            return;
        }

        // const shares = gen_cmd_matches.getMultiValues("shares").?;
        // var share_lists = std.ArrayList(std.ArrayList(u8)).init(allocator);
        // defer share_lists.deinit();
        //
        // for (shares) |raw_share| {
        //     // Input is expected to be in 2-digit hex format
        //     var buffer: [256]u8 = undefined;
        //     var i: usize = 0;
        //     while (i < raw_share.len) : (i += 2) {
        //         const raw_hex = raw_share[i .. i + 2];
        //         const hex = try std.fmt.parseInt(u8, raw_hex, 16);
        //         buffer[i / 2] = hex;
        //     }
        //     const s_slice = buffer[0 .. raw_share.len / 2];
        //     const share_list = std.ArrayList(u8).fromOwnedSlice(allocator, s_slice);
        //
        //     // Clone is required to prevent being overwritten
        //     // in subsequent iteration of loop
        //     const share_list_clone = try share_list.clone();
        //     try share_lists.append(share_list_clone);
        // }
        //
        // const share_lists_slice = try share_lists.toOwnedSlice();
        // const secret = try shamir.reconstruct(share_lists_slice, allocator);
        //
        // try stdout.print("Regenerated secret: ", .{});
        // for (secret.items) |s| {
        //     try stdout.print("{c}", .{s});
        // }

        try bw.flush();
    }
}
