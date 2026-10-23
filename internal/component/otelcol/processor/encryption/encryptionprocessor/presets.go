package encryptionprocessor

// preset is a well-known set of attributes carrying user or model content.
type preset struct {
	attributes []string
	patterns   []string
}

// presets maps preset names to attribute sets. They only list attributes
// whose value is content (prompts, completions, tool payloads); metadata such
// as model names, token counts or tool names stays in clear text so that the
// telemetry remains usable for technical monitoring.
var presets = map[string]preset{
	// OpenTelemetry GenAI semantic conventions, including the attributes of
	// the deprecated per-message events and of OpenLLMetry-style indexed
	// attributes.
	"gen_ai": {
		attributes: []string{
			"gen_ai.input.messages",
			"gen_ai.output.messages",
			"gen_ai.system_instructions",
			"gen_ai.tool.definitions",
			"gen_ai.tool.call.arguments",
			"gen_ai.tool.call.result",
			"gen_ai.prompt",
			"gen_ai.completion",
			"gen_ai.embeddings.input",
		},
		patterns: []string{
			`^gen_ai\.(prompt|completion)\.\d+\.`,
		},
	},
	// OpenInference semantic conventions (Arize Phoenix and compatible
	// instrumentations).
	"openinference": {
		attributes: []string{
			"input.value",
			"output.value",
			"llm.prompts",
			"llm.prompt_template.template",
			"llm.prompt_template.variables",
			"tool.parameters",
		},
		patterns: []string{
			`^llm\.(input|output)_messages\.`,
			`^embedding\.embeddings\.\d+\.embedding\.text$`,
			`^retrieval\.documents\.\d+\.document\.content$`,
		},
	},
	// Exception messages and stack traces, which often echo the prompt or
	// the payload that caused the error.
	"exceptions": {
		attributes: []string{
			"exception.message",
			"exception.stacktrace",
		},
	},
}
