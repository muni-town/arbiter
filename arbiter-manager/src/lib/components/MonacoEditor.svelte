<script lang="ts">
  import { Box } from '@foxui/core';
  import { onMount, onDestroy } from 'svelte';

  let {
    value = $bindable(),
    language = 'json',
    readOnly = false,
    onChange,
  }: {
    value?: string;
    language?: string;
    readOnly?: boolean;
    onChange?: (v: string) => void;
  } = $props();

  let containerEl: HTMLDivElement;
  let editor: any = null;

  // ── Rego language definition (used when language === 'rego') ──────────
  const regoLanguageConfig: any = {
    defaultToken: 'identifier',
    keywords: [
      'default', 'not', 'package', 'import', 'as', 'with', 'else',
      'some', 'in', 'every', 'if', 'contains',
    ],
    typeKeywords: ['true', 'false', 'null'],
    operators: [
      '=', '!=', '<', '>', '<=', '>=',
      '+', '-', '*', '/', '%',
      ':', ':=', '|', '&',
      '&&', '||',
    ],
    builtins: [
      'count', 'sum', 'max', 'min', 'product', 'any', 'all', 'sort', 'union', 'intersection',
      'sprintf', 'concat', 'replace', 'split', 'trim', 'trim_left', 'trim_right',
      'trim_prefix', 'trim_suffix', 'substring', 'contains', 'startswith', 'endswith',
      'indexof', 'last_indexof', 'lower', 'upper', 'format_int', 'reverse',
      're_match',
      'object.get', 'object.keys', 'object.union', 'object.remove', 'object.filter',
      'array.reverse', 'array.slice', 'array.concat',
      'is_number', 'is_string', 'is_boolean', 'is_array', 'is_set', 'is_object', 'is_null', 'type_name',
      'time.now_ns', 'time.parse_ns', 'time.parse_rfc3339_ns',
      'time.clock', 'time.date', 'time.diff',
      'opa.runtime', 'print', 'trace', 'walk', 'set',
      'xrpc_local', 'xrpc_remote',
    ],
    tokenizer: {
      root: [
        { include: '@whitespace' },
        [/\d+(\.\d+)?([eE][+-]?\d+)?/, 'number'],
        [/"/, { token: 'string.quote', next: '@stringDouble' }],
        [/`/, { token: 'string.quote', next: '@stringBacktick' }],
        [/#.*$/, 'comment'],
        [/[{}()\[\]]/, '@brackets'],
        [/[;,]/, 'delimiter'],
        [/[<>!=]=?/, 'delimiter'],
        [/&&|\|\||[+\-*/%:]/, 'delimiter'],
        [/[A-Z_][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*/, 'variable'],
        [/[a-z][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*/, {
          cases: {
            '@keywords': 'keyword',
            '@typeKeywords': 'type',
            '@builtins': 'type.identifier',
            '@default': 'identifier',
          },
        }],
      ],
      whitespace: [[/[ \t\r\n]+/, 'white']],
      stringDouble: [
        [/[^"\\]+/, 'string'],
        [/\\./, 'string.escape'],
        [/"/, { token: 'string.quote', next: '@pop' }],
      ],
      stringBacktick: [
        [/[^`\\]+/, 'string'],
        [/\\./, 'string.escape'],
        [/`/, { token: 'string.quote', next: '@pop' }],
      ],
    },
  };

  onMount(async () => {
    const monaco = await import('monaco-editor');
    // The DOM may have been detached/reattached while Monaco loaded (e.g. HMR);
    // bail out if our container is no longer attached, or `create` will walk
    // `parentNode` on a null/detached node.
    if (!containerEl?.isConnected) return;

    // ── Worker setup ─────────────────────────────────────────────────────
    const EditorWorker = (await import(
      'monaco-editor/esm/vs/editor/editor.worker?worker'
    )).default;
    const JsonWorker = (await import(
      'monaco-editor/esm/vs/language/json/json.worker?worker'
    )).default;
    if (!containerEl?.isConnected) return;

    (self as unknown as Record<string, unknown>).MonacoEnvironment = {
      getWorker(_: unknown, label: string) {
        if (label === 'json') return new JsonWorker();
        return new EditorWorker();
      },
    };

    // Register Rego language if needed
    if (language === 'rego') {
      monaco.languages.register({ id: 'rego' });
      monaco.languages.setMonarchTokensProvider('rego', regoLanguageConfig);
      monaco.languages.setLanguageConfiguration('rego', {
        comments: { lineComment: '#' },
        brackets: [
          ['{', '}'],
          ['[', ']'],
          ['(', ')'],
        ],
        autoClosingPairs: [
          { open: '{', close: '}' },
          { open: '[', close: ']' },
          { open: '(', close: ')' },
          { open: '"', close: '"' },
          { open: "'", close: "'" },
        ],
      });

      monaco.languages.registerCompletionItemProvider('rego', {
        provideCompletionItems: (_model: any, _position: any) => {
          const suggestions: any[] = [
            ...['package', 'import', 'default', 'if', 'else', 'not', 'some', 'in',
              'every', 'with', 'as', 'contains'].map((kw) => ({
              label: kw,
              kind: monaco.languages.CompletionItemKind.Keyword,
              insertText: kw,
              range: undefined as any,
            })),
            ...['count', 'sum', 'max', 'min', 'sprintf', 'concat', 'split',
              'startswith', 'endswith', 'contains', 'lower', 'upper',
              'object.get', 'object.keys', 'object.union',
              'is_string', 'is_number', 'is_array', 'is_object',
              'time.now_ns', 'time.clock', 'time.date', 'print', 'trace',
              'walk', 'set', 'xrpc_local', 'xrpc_remote',
            ].map((fn) => ({
              label: fn,
              kind: monaco.languages.CompletionItemKind.Function,
              insertText: fn,
              range: undefined as any,
            })),
          ];
          return { suggestions };
        },
      });
    }

    // Create editor
    editor = monaco.editor.create(containerEl, {
      value,
      readOnly,
      language,
      theme: 'vs-dark',
      minimap: { enabled: false },
      automaticLayout: true,
      fontSize: 13,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      wordWrap: 'on',
      tabSize: 2,
      padding: { top: 12, bottom: 12 },
      renderLineHighlight: 'line',
      folding: true,
      renderWhitespace: 'selection',
      bracketPairColorization: { enabled: true },
    });

    // Sync changes back
    editor.onDidChangeModelContent(() => {
      const text = editor.getValue();
      value = text;
      onChange?.(text);
    });
  });

  // Sync external value changes into the editor (if it's been created)
  $effect(() => {
    if (!editor || typeof value !== 'string') return;
    const current = value;
    if (editor.getValue() !== current) {
      editor.setValue(current);
    }
  });

  // Dispose the editor on unmount (incl. HMR re-mount) so Monaco doesn't leak
  // instances attached to detached DOM nodes.
  onDestroy(() => {
    editor?.dispose();
    editor = null;
  });
</script>

<Box class="p-0 overflow-hidden border border-base-200 dark:border-base-800 h-full">
  <div bind:this={containerEl} class="h-full"></div>
</Box>