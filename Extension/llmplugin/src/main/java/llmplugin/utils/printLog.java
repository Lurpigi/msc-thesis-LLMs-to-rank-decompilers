package llmplugin.utils;

import ghidra.app.services.ConsoleService;
import ghidra.util.Msg;

public class printLog{
	public printLog() {}
	
	public static void log(String msg, Object inputClass, ConsoleService console) {
		common(msg, console);
		Msg.info(inputClass, msg);
	}
	public static void err(String msg, Object inputClass, ConsoleService console) {
		common(msg, console);
		Msg.error(inputClass, msg);	
	}
	public static void warn(String msg, Object inputClass, ConsoleService console) {
		common(msg, console);
		Msg.warn(inputClass, msg);
	}
	
	private static void common(String msg, ConsoleService console) {
		if (console != null) {
			console.getStdOut().println(msg);
		}
	}
}