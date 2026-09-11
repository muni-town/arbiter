<script lang="ts">
  import MonacoEditor from './MonacoEditor.svelte';
  let {
    value = $bindable(),
    readOnly = false,
    onChange,
  }: { value?: string; readOnly?: boolean; onChange?: (v: string) => void } = $props();
</script>

<MonacoEditor {value} language="rego" {readOnly} {onChange} />