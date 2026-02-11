const std = @import("std");
const crypto = std.crypto;
const bcrypt = crypto.pwhash.bcrypt;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

pub const EncryptedData = struct {
    ciphertext: []const u8,
    nonce: [12]u8,
    tag: [16]u8,
    salt: [16]u8, // bcrypt KDF salt
};

pub const CryptoEngine = struct {
    derived_key: [32]u8,

    /// Initialize by deriving an AES-256 key from the master secret using bcrypt-pbkdf.
    /// The salt is fixed per-server lifetime (derived from the secret itself) so that
    /// the same key is derived each time without storing the salt separately.
    pub fn init(master_secret: []const u8) !CryptoEngine {
        // Derive a deterministic salt from the secret (so we always get the same key)
        var salt: [16]u8 = undefined;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(master_secret);
        h.update("sroolify-master-key-salt-v1");
        const digest = h.finalResult();
        @memcpy(&salt, digest[0..16]);

        var key: [32]u8 = undefined;
        try bcrypt.pbkdf(master_secret, &salt, &key, 16); // 16 rounds for KDF
        return .{ .derived_key = key };
    }

    /// Encrypt plaintext (e.g. an SSH private key) with AES-256-GCM.
    /// Returns allocated ciphertext + nonce + tag + per-item salt.
    pub fn encrypt(self: *const CryptoEngine, allocator: std.mem.Allocator, plaintext: []const u8) !EncryptedData {
        var nonce: [12]u8 = undefined;
        crypto.random.bytes(&nonce);

        var salt: [16]u8 = undefined;
        crypto.random.bytes(&salt);

        const ct = try allocator.alloc(u8, plaintext.len);
        var tag: [16]u8 = undefined;

        Aes256Gcm.encrypt(ct, &tag, plaintext, "", nonce, self.derived_key);

        return .{
            .ciphertext = ct,
            .nonce = nonce,
            .tag = tag,
            .salt = salt,
        };
    }

    /// Decrypt ciphertext back to plaintext.
    pub fn decrypt(self: *const CryptoEngine, allocator: std.mem.Allocator, enc: EncryptedData) ![]u8 {
        const plaintext = try allocator.alloc(u8, enc.ciphertext.len);
        errdefer allocator.free(plaintext);

        Aes256Gcm.decrypt(plaintext, enc.ciphertext, enc.tag, "", enc.nonce, self.derived_key) catch {
            allocator.free(plaintext);
            return error.DecryptionFailed;
        };

        return plaintext;
    }
};
