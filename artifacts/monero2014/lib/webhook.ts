
const WEBHOOK_URL = "https://your-domain.com/webhook";

export async function sendWebhook(payload: Record<string, unknown>): Promise<void> {
    const response = await fetch(WEBHOOK_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        throw new Error(
            `Webhook failed: ${response.status} ${response.statusText}`
        );
    }
}
