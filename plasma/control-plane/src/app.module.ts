import { Module, Controller, Get } from "@nestjs/common";
import { ToolsModule } from "./tools/tools.module";

@Controller()
export class AppController {
  @Get("/health")
  health(): { ok: boolean; pid: number; uptime_s: number } {
    return { ok: true, pid: process.pid, uptime_s: Math.round(process.uptime()) };
  }
}

@Module({ imports: [ToolsModule], controllers: [AppController] })
export class AppModule {}
