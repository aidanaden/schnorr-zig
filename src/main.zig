const std = @import("std");
const yazap = @import("yazap");
const schnorr = @import("schnorr.zig");
const musig2 = @import("musig2.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;

const App = yazap.App;
const Arg = yazap.Arg;

fn print_hex_from_bytes(bytes: []const u8, writer: std.io.AnyWriter) !void {
    for (0..bytes.len) |i| {
        try writer.print("{X:0>2}", .{bytes[i]});
    }
}

fn parse_raw_hex(raw_input: []const u8, allocator: std.mem.Allocator) !std.ArrayList([32]u8) {
    // raw input must contain at least 64 hex values
    // to map to a single 32-byte point or private key
    std.debug.assert(raw_input.len >= 64);

    var values = std.ArrayList([32]u8).init(allocator);
    var i: usize = 0;
    while (i < raw_input.len / 64) : (i += 1) {
        const raw_value = raw_input[i * 64 .. (i + 1) * 64];
        var buffer: [32]u8 = undefined;

        var j: usize = 0;
        while (j < raw_value.len) : (j += 2) {
            const raw_hex = raw_value[j .. j + 2];
            const hex = try std.fmt.parseInt(u8, raw_hex, 16);
            buffer[j / 2] = hex;
        }
        try values.append(buffer);
    }
    return values;
}

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    const stdout_any = stdout.any();
    var start: usize = 0;
    _ = &start;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var app = App.init(allocator, "schnorr", "Schnorr Signing (via Ristretto255) CLI tool");
    defer app.deinit();

    var cli = app.rootCommand();

    var keygen_cmd = app.createCommand("keygen", "Generate a public/private key pair with 2 public/private nonces (to be used for musig2)");
    try keygen_cmd.addArg(Arg.singleValueOption("count", 'c', "Number of public/private key pairs + nonces to generate"));
    try cli.addSubcommand(keygen_cmd);

    var sign_cmd = app.createCommand("sign", "Generate a schnorr signature of a message given a private key");
    try sign_cmd.addArg(Arg.singleValueOption("priv", 'p', "Private key for signing"));
    try sign_cmd.addArg(Arg.singleValueOption("message", 'm', "Message to sign"));
    try cli.addSubcommand(sign_cmd);

    var musig2_sign_cmd = app.createCommand("partial", "Generate a partial musig2 signature of a message given a private key");
    try musig2_sign_cmd.addArg(Arg.singleValueOption("priv", 'p', "Private key for signing"));
    try musig2_sign_cmd.addArg(Arg.singleValueOption("nonce", 'n', "Private nonce for signing"));
    try musig2_sign_cmd.addArg(Arg.singleValueOption("message", 'm', "Message to sign"));
    try musig2_sign_cmd.addArg(Arg.multiValuesOption("pubkeys", null, "Public keys of all signers involved", 255));
    try musig2_sign_cmd.addArg(Arg.multiValuesOption("pubnonces", null, "Public nonces of all signers involved", 255));

    var musig2_aggregate_cmd = app.createCommand("aggregate", "Generate an aggregated signature from a list of partial signatures via musig2");
    try musig2_aggregate_cmd.addArg(Arg.multiValuesOption("signatures", 's', "Partial signatures to generate an aggregate signature from", 255));

    var musig2_cmd = app.createCommand("musig2", "Sign a message with multiple partial signatures via musig2");
    try musig2_cmd.addSubcommand(musig2_sign_cmd);
    try musig2_cmd.addSubcommand(musig2_aggregate_cmd);
    try cli.addSubcommand(musig2_cmd);

    var verify_cmd = app.createCommand("verify", "Verify a signature given the signer's public key");
    try verify_cmd.addArg(Arg.singleValueOption("pub", 'p', "Signer's public key"));
    try verify_cmd.addArg(Arg.singleValueOption("message", 'm', "Message used to generate signature"));
    try verify_cmd.addArg(Arg.singleValueOption("signature", 's', "Signature to verify"));
    try cli.addSubcommand(verify_cmd);

    const matches = try app.parseProcess();

    if (matches.subcommandMatches("keygen")) |keygen_cmd_matches| {
        if (keygen_cmd_matches.getSingleValue("count") == null) {
            try stdout.print("Please provide number of public/private key pairs to generate", .{});
            try bw.flush();
            return;
        }

        const raw_count = keygen_cmd_matches.getSingleValue("count").?;
        const count = try std.fmt.parseInt(u8, raw_count, 10);

        for (0..count) |i| {
            if (i > 0) {
                try stdout.print("\n", .{});
            }
            try stdout.print("=== Set {} ===", .{i + 1});

            const keypair = try schnorr.generate_keypair();
            try stdout.print("\nPublic key: ", .{});
            const pub_bytes = keypair.pub_point.toBytes();
            try print_hex_from_bytes(pub_bytes[start..], stdout_any);

            try stdout.print("\nPrivate key: ", .{});
            try print_hex_from_bytes(&keypair.priv_key, stdout_any);

            const nonce1 = try schnorr.generate_keypair();
            try stdout.print("\nPublic nonce 1: ", .{});
            try print_hex_from_bytes(nonce1.pub_point.toBytes()[start..], stdout_any);
            try stdout.print("\nPrivate nonce 1: ", .{});
            try print_hex_from_bytes(&nonce1.priv_key, stdout_any);

            const nonce2 = try schnorr.generate_keypair();
            try stdout.print("\nPublic nonce 2: ", .{});
            try print_hex_from_bytes(nonce2.pub_point.toBytes()[start..], stdout_any);
            try stdout.print("\nPrivate nonce 2: ", .{});
            try print_hex_from_bytes(&nonce2.priv_key, stdout_any);

            try stdout.print("\n", .{});
        }
        try bw.flush();
    }

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

        const message = sign_cmd_matches.getSingleValue("message").?;
        const raw_privkey = sign_cmd_matches.getSingleValue("priv").?;
        if (raw_privkey.len != 64) {
            try stdout.print("Only 1 private key allowed! (expected 64 hex values)", .{});
            try bw.flush();
            return;
        }
        const privkey_list = try parse_raw_hex(raw_privkey, allocator);
        const privkey = privkey_list.items[0];

        const pubkey = try Ristretto255.basePoint.mul(privkey);
        const pubkey_bytes = pubkey.toBytes();
        try stdout.print("Public key: ", .{});
        try print_hex_from_bytes(pubkey_bytes[start..], stdout_any);

        const sig = try schnorr.Signature.sign(message, &privkey, allocator);
        try stdout.print("\nSignature: ", .{});
        try sig.print_hex(stdout_any);

        try bw.flush();
    }

    if (matches.subcommandMatches("musig2")) |musig_cmd_matches| {
        if (musig_cmd_matches.subcommandMatches("partial")) |musig_sign_matches| {
            if (musig_sign_matches.getSingleValue("priv") == null) {
                try stdout.print("Please provide private key for signing", .{});
                try bw.flush();
                return;
            }

            if (musig_sign_matches.getSingleValue("nonce") == null) {
                try stdout.print("Please provide private nonce for signing", .{});
                try bw.flush();
                return;
            }
            if (musig_sign_matches.getSingleValue("message") == null) {
                try stdout.print("Please provide message to sign", .{});
                try bw.flush();
                return;
            }
            if (musig_sign_matches.getMultiValues("pubkeys") == null) {
                try stdout.print("Please provide all signers public keys", .{});
                try bw.flush();
                return;
            }
            if (musig_sign_matches.getMultiValues("pubnonces") == null) {
                try stdout.print("Please provide all signers public nonces", .{});
                try bw.flush();
                return;
            }

            const message = musig_sign_matches.getSingleValue("message").?;

            const raw_privkey = musig_sign_matches.getSingleValue("priv").?;
            if (raw_privkey.len != 64) {
                try stdout.print("Only 1 private key allowed! (expected 64 hex values)", .{});
                try bw.flush();
                return;
            }
            const privkey_list = try parse_raw_hex(raw_privkey, allocator);
            defer privkey_list.deinit();
            const privkey = privkey_list.items[0];

            const raw_signer_nonce = musig_sign_matches.getSingleValue("nonce").?;
            if (raw_signer_nonce.len != 128) {
                try stdout.print("Invalid signer nonce! (expected 128 hex values)", .{});
                try bw.flush();
                return;
            }
            var signer_nonce_list = try parse_raw_hex(raw_signer_nonce, allocator);
            defer signer_nonce_list.deinit();
            const signer_nonce = try signer_nonce_list.toOwnedSlice();
            defer allocator.free(signer_nonce);

            var pubkeys = std.ArrayList(Ristretto255).init(allocator);
            defer pubkeys.deinit();
            const raw_pubkeys = musig_sign_matches.getMultiValues("pubkeys").?;
            for (0..raw_pubkeys.len) |i| {
                const raw_pubkey = raw_pubkeys[i];
                const pubkey_list = try parse_raw_hex(raw_pubkey, allocator);
                const pubkey_bytes = pubkey_list.items[0];
                const pubkey = try Ristretto255.fromBytes(pubkey_bytes);
                try pubkeys.append(pubkey);
            }

            var nonces = std.ArrayList([2]Ristretto255).init(allocator);
            defer nonces.deinit();
            // 2 nonce points are expected in each raw nonce input value
            // (64 hex characters per nonce point, 128 hex characters each)
            const raw_nonces = musig_sign_matches.getMultiValues("pubnonces").?;
            for (0..raw_nonces.len) |i| {
                const raw_nonce = raw_nonces[i];
                const nonce_list = try parse_raw_hex(raw_nonce, allocator);
                if (nonce_list.items.len != 2) {
                    try stdout.print("2 nonces required! (expected 128 hex values)", .{});
                    try bw.flush();
                    return;
                }
                const nonce1_bytes = nonce_list.items[0];
                const nonce1 = try Ristretto255.fromBytes(nonce1_bytes);

                const nonce2_bytes = nonce_list.items[1];
                const nonce2 = try Ristretto255.fromBytes(nonce2_bytes);

                const nonce = [_]Ristretto255{ nonce1, nonce2 };
                try nonces.append(nonce);
                nonce_list.deinit();
            }

            const aggregated_pubkey = try musig2.compute_aggregate_pubkey(pubkeys, allocator);
            const aggregated_point = aggregated_pubkey.point.toBytes();
            try stdout.print("\nAggregated public key: ", .{});
            try print_hex_from_bytes(aggregated_point[start..], stdout_any);

            const sig = try musig2.sign_partial(&privkey, signer_nonce, &aggregated_pubkey, nonces, message, allocator);
            try stdout.print("\nPartial signature: ", .{});
            try sig.print_hex(stdout_any);
            try bw.flush();
        }

        if (musig_cmd_matches.subcommandMatches("aggregate")) |musig_aggregate_matches| {
            if (musig_aggregate_matches.getMultiValues("signatures") == null) {
                try stdout.print("Please provide all partial signatures", .{});
                try bw.flush();
                return;
            }
            const raw_signatures = musig_aggregate_matches.getMultiValues("signatures").?;
            var signatures = std.ArrayList(schnorr.Signature).init(allocator);
            defer signatures.deinit();
            for (0..raw_signatures.len) |i| {
                const raw_signature = raw_signatures[i];
                const sig_bytes_list = try parse_raw_hex(raw_signature, allocator);
                const sig = schnorr.Signature{ .nonce_pub = sig_bytes_list.items[0], .s = sig_bytes_list.items[1] };
                try signatures.append(sig);
            }

            for (0..signatures.items.len) |i| {
                const sig = signatures.items[i];
                try stdout.print("\nPartial signature: ", .{});
                try sig.print_hex(stdout_any);
            }

            const sig = try musig2.sign_aggregate(signatures);
            try stdout.print("\nsignature: ", .{});
            try sig.print_hex(stdout_any);
            try bw.flush();
        }
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

        const raw_message = verify_cmd_matches.getSingleValue("message").?;

        const raw_pubkey = verify_cmd_matches.getSingleValue("pub").?;
        const pubkey_list = try parse_raw_hex(raw_pubkey, allocator);
        if (pubkey_list.items.len > 1) {
            try stdout.print("Only 1 public key allowed! (expected 64 hex values)", .{});
            try bw.flush();
            return;
        }
        const pubkey_bytes = pubkey_list.items[0];
        const pubkey = try Ristretto255.fromBytes(pubkey_bytes);

        const raw_sig = verify_cmd_matches.getSingleValue("signature").?;
        const sig_bytes = try parse_raw_hex(raw_sig, allocator);
        std.debug.assert(sig_bytes.items.len == 2);

        const sig_nonce_pubkey = sig_bytes.items[0];
        const sig_s = sig_bytes.items[1];

        const sig = schnorr.Signature{ .nonce_pub = sig_nonce_pubkey, .s = sig_s };
        const valid = try sig.verify(&pubkey, raw_message, allocator);

        try stdout.print("\nsignature validity: {any}", .{valid});
        try bw.flush();
    }
}

test {
    @import("std").testing.refAllDecls(musig2);
}

// Public key: 4AA4DA8E9A19366B175E8294B58F76F234295AED642125389FF6561338CFFD67
// Private key: 65D07888FBBBD5C5910A0C7ED888E3E8F9183199E5EAE4AC4BB20610CCBBB90C
// Public key: 1EB2EC8F8F59D7B72A79E1F5C39F9FBF6A51F0C9805059AA14069762A5BE991A
// Private key: 2EA6618032CE29913DCB753BD38E2A18432D9BF701377AEB4E3B8083FD1C30C0
// Public key: 24F8A9C932D55B2782F559D6C22B3A93EF9096D16A8CCF45063318542A376559
// Private key: 21D29026BB188C2C21C44626DB69DC45AACC2C5CD8E52359965C09C708A6A658
// Public key: 6494E56E5B35FDE4F66EBDCE75B15595014957034CE8D0761E543ED891FABA20
// Private key: 1678596EB75FA6E82C2E1EA2EA5477E47E983990AD1F6128A233CF8EAA744EEC
// Public key: 72B0DDE18589CEABEC6C10D8F6963717AB1621A739EAA87FA5C58B18F3E6CA12
// Private key: 040EE75FA1963AC588AD1A8DA87A6C407AB8F5BB01DED16A146C0848AD891CDB
// Public key: AE57B775BD6DF8C436B9442E1FB946FC15435968185D0C33FDBE46AFB60BBF28
// Private key: 4655A10D5D506BE4DE0EE7C2F03C321A788F7FF3963E4A62702115D4F447E116

// ./zig-out/bin/schnorr musig2 partial -m oknigga --pubkeys=4AA4DA8E9A19366B175E8294B58F76F234295AED642125389FF6561338CFFD67,6494E56E5B35FDE4F66EBDCE75B15595014957034CE8D0761E543ED891FABA20 --pubnonces=1EB2EC8F8F59D7B72A79E1F5C39F9FBF6A51F0C9805059AA14069762A5BE991A24F8A9C932D55B2782F559D6C22B3A93EF9096D16A8CCF45063318542A376559,72B0DDE18589CEABEC6C10D8F6963717AB1621A739EAA87FA5C58B18F3E6CA12AE57B775BD6DF8C436B9442E1FB946FC15435968185D0C33FDBE46AFB60BBF28 --priv 65D07888FBBBD5C5910A0C7ED888E3E8F9183199E5EAE4AC4BB20610CCBBB90C --nonce 2EA6618032CE29913DCB753BD38E2A18432D9BF701377AEB4E3B8083FD1C30C021D29026BB188C2C21C44626DB69DC45AACC2C5CD8E52359965C09C708A6A658

// ./zig-out/bin/schnorr musig2 partial -m oknigga --pubkeys=4AA4DA8E9A19366B175E8294B58F76F234295AED642125389FF6561338CFFD67,6494E56E5B35FDE4F66EBDCE75B15595014957034CE8D0761E543ED891FABA20 --pubnonces=1EB2EC8F8F59D7B72A79E1F5C39F9FBF6A51F0C9805059AA14069762A5BE991A24F8A9C932D55B2782F559D6C22B3A93EF9096D16A8CCF45063318542A376559,72B0DDE18589CEABEC6C10D8F6963717AB1621A739EAA87FA5C58B18F3E6CA12AE57B775BD6DF8C436B9442E1FB946FC15435968185D0C33FDBE46AFB60BBF28 --priv 1678596EB75FA6E82C2E1EA2EA5477E47E983990AD1F6128A233CF8EAA744EEC --nonce 040EE75FA1963AC588AD1A8DA87A6C407AB8F5BB01DED16A146C0848AD891CDB4655A10D5D506BE4DE0EE7C2F03C321A788F7FF3963E4A62702115D4F447E116

// ./zig-out/bin/schnorr musig2 aggregate --signatures=1E2C37CDB141D853BA8E36A539FAF8F550D1BA4E4F9359FA9E87B6CDE9B86A121DB53F27E4657BDFFF60979A082ECD350FB4F7716A722054E087C8A4B8C74804,1E2C37CDB141D853BA8E36A539FAF8F550D1BA4E4F9359FA9E87B6CDE9B86A12B231A571BB6BC71367CA79854AE1DEA0BB1D61490270F284A110FDB0C928640B
