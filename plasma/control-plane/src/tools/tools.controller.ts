import { Body, Controller, Get, Post } from "@nestjs/common";
import { ToolsService, type RunResult } from "./tools.service";

interface RunBody {
  tool: string;
  args?: unknown[];
  elevated?: boolean;
  timeout_ms?: number;
}

@Controller("tools")
export class ToolsController {
  constructor(private readonly tools: ToolsService) {}

  @Get()
  list(): ReturnType<ToolsService["list"]> {
    return this.tools.list();
  }

  @Post("run")
  run(@Body() body: RunBody): Promise<RunResult> {
    const args = body?.args ?? [];
    const timeout = Number(body?.timeout_ms ?? 30_000);
    return this.tools.run(String(body?.tool ?? ""), args, Boolean(body?.elevated), timeout);
  }
}
