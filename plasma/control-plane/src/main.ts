import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { Logger } from "@nestjs/common";
import { AppModule } from "./app.module";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? "127.0.0.1"; // loopback by default; never 0.0.0.0 here
  await app.listen(port, host);
  Logger.log(`plasma listening on http://${host}:${port}`, "bootstrap");
}

void bootstrap();
