import amqp from "amqplib";
import dotenv from "dotenv";
dotenv.config();
let channel;

export async function emitAudit(event) {
    console.log("Emitting audit event:", event);
    console.log("The URL is:",process.env.RABBIT_URL)
  if (!channel) {
    const conn = await amqp.connect(process.env.RABBIT_URL);
    channel = await conn.createChannel();
    await channel.assertQueue("audit_logs", { durable: true });
  }

  channel.sendToQueue(
    "audit_logs",
    Buffer.from(JSON.stringify(event)),
    { persistent: true }
  );
}
