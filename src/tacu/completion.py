'''Shell completion and conservative TACU-only ghost suggestions.'''

from __future__ import annotations

import os
from pathlib import Path

from .core import TacuError

COMMANDS = (
    "help tacu do propose plan auto web ask analyze run companion focus docker inspect "
    "history menu review report evidence copy clip tray syntax save extract juicy data dataset "
    "backup all tutorial guide completion shell-init version models model config plugins doctor "
    "health setup workspace tools tool clear"
)
BACKUP_ACTIONS = "create list show restore"
DATA_ACTIONS = "load list show head ask query search juicy rm gc enrich"
TOOLS = "repo_map search_code read_file inspect_symbol edit_file write_file shell diagnostics run_tests task_state process network system application ollama filesystem git docker service package security"
TOOL_ACTIONS = "list examples describe map find search read write edit run"
HELP_TOPICS = (
    "ask auto do run inspect web docker tools juicy extract data review evidence copy clip syntax "
    "save clear backup workspace doctor health setup model models config plugins completion "
    "shell-init version all tacu safety memory automation questions commands"
)


def detect_shell() -> str:
    if os.name == "nt":
        return "powershell"
    return Path(os.environ.get("SHELL", "zsh")).name or "zsh"


def zsh_completion() -> str:
    return r'''#compdef ticu ti
_tacu() {
  local -a commands command_descs tool_actions tool_action_descs tools
  local -a config_actions model_actions workspace_actions
  commands=(
    do propose plan auto web ask analyze run docker inspect config workspace
    health review report evidence copy clip tray syntax save extract juicy tools tool all     help tacu
    shell-init     completion version model models setup plugins clear history menu doctor backup data
  )
  command_descs=(
    'propose commands for review before execution'
    'alias for do'
    'alias for do'
    'autonomously run safe steps; pause at policy gates'
    'local SearXNG search and guarded public page reads'
    'ask a question or analyze piped output'
    'alias for ask'
    'run a local command and answer -q from its stdout'
    'run a tool inside a container'
    'colorize YOUR stdout; no model'
    'change model and context'
    'select or enter a workspace'
    'check TACU readiness'
    'browse stored turns'
    'alias for review'
    'show secured raw evidence for a retained turn'
    'copy answer line or block'
    'clipboard tray'
    'alias for clip'
    'OS command cookbook'
    'export a response'
    'extract juicy information'
    'inventory secrets before any model'
    'invoke native tools'
    'alias for tools'
    'full tutorial'
    'focused help'
    'AI-assisted help with examples'
    'activate shell support'
    'print shell completion'
    'show installed version'
    'change model'
    'list models'
    'finish setup'
    'list extensions'
    'clear retained history'
    'browse stored turns'
    'browse stored turns'
    'check readiness'
    'save or restore all TACU data'
    'query a large file'
  )
  tool_actions=(list examples describe map find search read write edit run)
  tool_action_descs=(
    'list tool contracts'
    'show native-tool recipes'
    'show one contract'
    'map a directory to a chosen depth'
    'find files by name'
    'search text with file and line output'
    'read numbered file lines'
    'create a workspace file'
    'replace exact text in a file'
    'invoke the advanced JSON contract'
  )
  tools=(${=TACU_COMPLETION_TOOLS:-repo_map search_code read_file inspect_symbol edit_file write_file shell diagnostics run_tests task_state process network system application ollama filesystem git docker service package security})
  config_actions=(show update reset)
  model_actions=(current list use reset)
  workspace_actions=(show enter create use)
  if [[ $words[1] == noglob ]]; then
    shift words
    (( CURRENT-- ))
  fi
  if (( CURRENT == 2 )); then
    # Matches stay short names; descriptions are display-only (never inserted).
    compadd -Q -d command_descs -a commands
    return
  fi
  case $words[2] in
    tools|tool)
      if (( CURRENT == 3 )); then
        compadd -Q -d tool_action_descs -a tool_actions
        return
      fi
      case $words[3] in
        describe)
          (( CURRENT == 4 )) && _describe -t tools 'native tool' tools
          ;;
        run)
          if (( CURRENT == 4 )); then _describe -t tools 'native tool' tools; return; fi
          _arguments '--input=[JSON object]:json:' '--workspace=[workspace]:directory:_directories' '--approve[approve a policy-flagged command]'
          ;;
        map) _arguments '1:directory:_directories' '--depth=[tree depth]:depth:(2 3 4 5 6)' '--symbols[include Python symbols]' '--max-files=[limit]:count:' '--json[JSON output]' ;;
        find) _arguments '1:name or glob:' '2:directory:_directories' '--type=[entry type]:type:(file directory any)' '--case-sensitive[match exact case]' '--case-insensitive[ignore case; default]' '--max-results=[limit]:count:' '--json[JSON output]' ;;
        search) _arguments '1:text or pattern:' '2:directory:_directories' '--regex[use regular expression]' '--case-sensitive[match exact case]' '--case-insensitive[ignore case; default]' '--glob=[file glob]:glob:' '--max-results=[limit]:count:' '--json[JSON output]' ;;
        read) _arguments -C \
          '--start=[first line]:line:' \
          '--end=[last line]:line:' \
          '--json[JSON output]' \
          '*:file:_files' ;;
        write) _arguments -C \
          '--content=[file body]:text:' \
          '--overwrite[replace an existing file]' \
          '--json[JSON output]' \
          '*:file:_files' ;;
        edit) _arguments -C \
          '--old=[exact text to replace]:text:' \
          '--new=[replacement text]:text:' \
          '--expected-count=[match count]:count:' \
          '--json[JSON output]' \
          '*:file:_files' ;;
      esac ;;
    do|propose|plan|auto) _arguments '--workspace=[workspace boundary]:directory:_directories' '--max-steps=[step limit]:count:(1 2 3 4 5)' '--dry-run[show plan without execution]' '*:intent words:' ;;
    ask|analyze) _arguments \
      '--keys=[JSON keys to keep]:keys:' \
      '--cols=[CSV columns to keep]:columns:' \
      '--path=[JSON dotted path]:path:' \
      '--grep=[match text]:pattern:' \
      '--head=[first N rows/lines]:count:' \
      '--tail=[last N lines]:count:' \
      '--limit=[max rows/lines]:count:' \
      '--no-ai[filtered ingest only; no model]' \
      '*:question words:'
      ;;
    web) _arguments '--results=[search result limit]:count:(5 8 10 12 20)' '--read=-[public pages to read]:count:(0 1 2 3 4 5)' '--snippets[search snippets only]' '--no-ai[list sources without synthesis]' '--json[structured retrieval output]' '1:mode or query:(search fetch health)' '*:query words or public URL:' ;;
    config)
      if (( CURRENT == 3 )); then _values 'config action' $config_actions; return; fi
      [[ $words[3] == update ]] && _arguments '--model=[model]:model:_tacu_models' '--context-turns=[history turns]:count:(0 1 3 5 8 10)'
      ;;
    model)
      if (( CURRENT == 3 )); then _values 'model action' $model_actions; return; fi
      [[ $words[3] == use ]] && _tacu_models
      ;;
    workspace)
      if (( CURRENT == 3 )); then _values 'workspace action' $workspace_actions; return; fi
      [[ $words[3] == (create|use) ]] && _directories
      ;;
    extract) _arguments '1:kind:(juicy)' '2:file:_files' '--format=[format]:format:(csv json jsonl txt)' '-o[output]:file:_files' '--output=[file]:file:_files' '--min-confidence=[level]:level:(critical high medium low)' '--kind=[kinds]:kinds:' '--grep=[value text]:text:' '--ask=[question]:question:' '--reports=[dir]:dir:_directories' '--resume' '--all-files' ;;
    juicy) _arguments '1:file or directory:_files' '--format=[format]:format:(csv json jsonl txt)' '-o[output]:file:_files' '--min-confidence=[level]:level:(critical high medium low)' '--kind=[kinds]:kinds:' '--grep=[value text]:text:' '--ask=[question]:question:' '--reports=[dir]:dir:_directories' '--resume' '--all-files' ;;
    save) _arguments '1:turn id:' '--format=[format]:format:(md txt json)' '--output=[file]:file:_files' ;;
    evidence) _arguments '1:turn id:' ;;
    copy)
      _arguments \
        '1:turn, last, last:line, or last:a-b:' \
        '--block=[code block N or N:line]:block:' \
        '--command=[recipe id or search]:recipe:' \
        '--to-clip[add selection to tray]' \
        '--label=[tray label with --to-clip]:label:'
      ;;
    syntax)
      local -a syntax_actions syntax_action_descs
      syntax_actions=(list search show seed add rm clear)
      syntax_action_descs=(
        'show cookbook' 'filter recipes' 'print recipe' 'built-in host recipes'
        'index manual argv' 'delete' 'empty cookbook'
      )
      if (( CURRENT == 3 )); then
        compadd -Q -d syntax_action_descs -a syntax_actions
        return
      fi
      case $words[3] in
        search|find) _message 'search text' ;;
        show|rm|delete) _message 'recipe id' ;;
        add) _arguments '--label=[label]:label:' '*:argv:' ;;
        clear) _arguments '--yes[confirm clear]' ;;
      esac
      ;;
    clip|tray)
      local -a clip_actions clip_action_descs
      clip_actions=(list status add show edit rm search clear copy)
      clip_action_descs=(
        'show tray' 'count' 'create item' 'print body' 'update body/label'
        'delete' 'filter' 'empty tray' 'OS clipboard from tray #'
      )
      if (( CURRENT == 3 )); then
        compadd -Q -d clip_action_descs -a clip_actions
        return
      fi
      case $words[3] in
        add) _arguments '--from-turn=[turn:line]:turn:' '--block=[block]:block:' '--label=[label]:label:' '*:text:' ;;
        edit) _arguments '--label=[label only]:label:' '1:tray id:' '*:new text:' ;;
        show|rm|delete|copy|paste) _message 'tray id' ;;
        search) _message 'query' ;;
        clear) _arguments '--yes[confirm clear]' ;;
      esac
      ;;
    data|dataset)
      local -a data_actions data_action_descs
      data_actions=(load list show head ask query search juicy rm gc enrich)
      data_action_descs=(
        'stream a CSV, JSON, PCAP, SQLite backup or XLSX file into a store' 'show loaded datasets'
        'describe the columns' 'print the first rows' 'ask in plain language'
        'run one read-only SELECT'
        'find rows containing text' 'remove a dataset' 'delete expired datasets'
        'rebuild a capture with src_name/dst_name from DNS, SNI and Host'
      )
      if (( CURRENT == 3 )); then
        compadd -Q -d data_action_descs -a data_actions
        return
      fi
      case $words[3] in
        load|add) _arguments '--name[short handle (default dt1, dt2, …)]:name:' '--ttl[hours before sweep]:hours:' \
          '--delimiter[force a separator]:delimiter:' '--header[first row contains column names]' \
          '--no-header[first row is data]' \
          '--format[force a format]:format:(csv ndjson json xlsx pcap sqlite text registry burp)' \
          '--path[JSON key holding the records]:key:' \
          '--sheet[XLSX sheet name]:sheet:' \
          '--depth[levels of nesting to flatten]:levels:(1 2 3)' \
          '1:file:_files -g "*.(csv|tsv|txt|json|ndjson|jsonl|xlsx|xlsm|pcap|pcapng|cap|bak|db|dat|xml|burp)"' ;;
        ask|q) _arguments '--steps[maximum queries the model may run]:count:' \
          '--sql-only[show the SQL without running it]' \
          '1:dataset:($(command ticu __data-names 2>/dev/null))' ;;
        juicy|ji) _arguments '--limit[max findings]:count:' '--kind[kinds]:kinds:' \
          '--grep[value text]:text:' \
          '1:dataset:($(command ticu __data-names 2>/dev/null))' \
          '*:question:' ;;
        show|profile|schema|head|query|sql|search|grep|rm|drop|delete|enrich|names|resolve)
          _values 'dataset' ${(f)"$(command ticu __data-names 2>/dev/null)"} ;;
      esac
      ;;
    backup)
      local -a backup_actions backup_action_descs
      backup_actions=(create list show restore)
      backup_action_descs=(
        'write a portable .tar.gz' 'show backups in a folder'
        'describe one archive' 'put the data back'
      )
      if (( CURRENT == 3 )); then
        compadd -Q -d backup_action_descs -a backup_actions
        return
      fi
      case $words[3] in
        create|save) _arguments '--include-artifacts[also store raw command output]' '1:folder or archive:_files' ;;
        list|ls) _arguments '1:folder:_directories' ;;
        show|inspect) _arguments '1:archive:_files -g "*.tar.gz"' ;;
        restore) _arguments '--merge[keep local data; add only what is missing]' '--yes[skip confirmation]' \
          '--no-safety-copy[do not snapshot current state first]' '1:archive:_files -g "*.tar.gz"' ;;
      esac
      ;;
    completion|shell-init) _values 'shell' zsh bash fish powershell ;;
    help) _values 'topic' ask auto do run inspect web docker tools juicy extract data review evidence copy clip syntax save clear backup workspace doctor health setup model models config plugins completion shell-init version all tacu safety memory automation questions commands ;;
    history|menu|review|report)
      local -a hist_actions hist_action_descs
      hist_actions=(list search find)
      hist_action_descs=('show turns' 'filter turns' 'alias for search')
      if (( CURRENT == 3 )); then
        compadd -Q -d hist_action_descs -a hist_actions
        _arguments '--list[list only]'
        return
      fi
      case $words[3] in
        search|find) _message 'search text' ;;
        list) ;;
      esac
      ;;
    run)
      _arguments \
        '-q[question to answer from command stdout]:question:' \
        '--shell[run COMMAND through a shell]' \
        '*::command:_command'
      ;;
    inspect) _arguments '--shell[use a shell]' '*::command:_command' ;;
    docker) _arguments '1:container:' '-q[question]:question:' '*::command:_command' ;;
    health|doctor) _arguments '--json[JSON output]' '--workspace=[workspace]:directory:_directories' ;;
    setup) _arguments '--workspace=[workspace]:directory:_directories' '--use-current[use cwd]' '--skip-models[skip model pull]' '--force[re-run setup]' ;;
    *) _files ;;
  esac
}
_tacu_models() {
  local -a models
  if (( $+commands[ollama] )); then
    models=(${(f)"$(command ollama list 2>/dev/null | command awk 'NR>1 {print $1}')"})
  fi
  _describe -t models 'installed Ollama model' models
}
compdef _tacu ticu ti
'''


def zsh_ghost() -> str:
    return r'''# TACU layered ghosts: L1/L2 structural → L3 history → L4 semantic → L5 async model (opt-in).
# Tab = deterministic completion (never blocks on a model). → / End / Ctrl-E = accept dim ghost.
if [[ -o interactive ]] && (( $+functions[add-zle-hook-widget] == 0 )); then
  autoload -Uz add-zle-hook-widget
fi
if [[ -o interactive && "${TACU_GHOST_PROMPTS:-1}" != 0 ]]; then
  typeset -ga TACU_GHOST_COMMANDS TACU_GHOST_TOOL_ACTIONS TACU_GHOST_HELP_TOPICS TACU_GHOST_BACKUP_ACTIONS TACU_GHOST_DATA_ACTIONS
  typeset -ga TACU_GHOST_EXAMPLES
  TACU_GHOST_COMMANDS=(
    do propose plan auto web ask analyze run docker inspect config workspace health
    review report copy clip tray syntax save extract juicy tools tool all help tacu shell-init
    completion version model models setup plugins clear history menu doctor backup data
  )
  TACU_GHOST_TOOL_ACTIONS=(list examples describe map find search read write edit run)
  TACU_GHOST_BACKUP_ACTIONS=(create list show restore)
  TACU_GHOST_DATA_ACTIONS=(load list show head ask query search juicy rm gc enrich)
  TACU_GHOST_HELP_TOPICS=(
    ask auto do run inspect web docker tools juicy extract data review evidence copy
    clip syntax save clear backup workspace doctor health setup model models config
    plugins completion shell-init version all tacu safety memory automation questions commands
  )
  TACU_GHOST_EXAMPLES=(
    'ti help' 'ti help run' 'ti help juicy' 'ti help extract' 'ti help docker' 'ti help syntax'
    'ti help clip' 'ti help health' 'ti tacu help' 'ti tacu help data' 'ti version' 'ti all' 'ti health' 'ti doctor'
    'ti config show' 'ti config update --model gemma4:12b-mlx --context-turns 5'
    'ti do find the ten largest files in this workspace'
    'ti auto --dry-run which process is consuming most CPU'
    'ti auto which process is consuming most CPU'
    'ti auto top 3 processes consuming most CPU'
    'ti auto top tcp 443 destinations'
    'ti web current macOS security updates' 'ti web --snippets latest AI security news'
    'ti web health' 'ti web fetch https://example.com/'
    'ti tools examples' 'ti tools list' 'ti tools map . --depth 3'
    'ti tools write hello.py --content print(1)' 'ti tools edit app.py --old foo --new bar'
    'ti tools run process --input {"operation":"top_cpu","limit":10}'
    'ti tools run network --input {"operation":"connections","state":"ESTABLISHED"}'
    'ti tools find "*.yaml" .' 'ti tools search TODO . --glob "*.py"'
    'ti copy last' 'ti copy last:1' 'ti copy last:2-3' 'ti copy 42' 'ti copy 42:3' 'ti copy 42:3 --to-clip' 'ti copy last --block 1'
    'ti save 42 --format md'
    'ti clip' 'ti clip list' 'ti clip add "' 'ti clip 3' 'ti clip show 3'
    'ti clip edit 3 "' 'ti clip rm 3' 'ti clip search ' 'ti clip clear --yes'
    'ti review' 'ti review --list' 'ti review search ' 'ti history search '
    'ti syntax' 'ti syntax search cpu' 'ti syntax 3' 'ti copy --command'
    'ti run -q what is my primary IP -- ifconfig'
    'ti extract juicy findings.txt -o findings.csv'
    'ti juicy findings.txt -o findings.csv'
    'ti juicy findings.txt --grep 9870000043'
    'ti juicy . --kind indian-phone --grep 9870000043'
    'ti model use gemma4:12b-mlx' 'ti model current' 'ti model list'
    'ti workspace show' 'ti workspace use ' 'ti workspace create ' 'ti workspace enter'
    'ti ask explain DNS caching' 'ti inspect -- ifconfig'
    'ti backup create ~/Desktop' 'ti backup create --include-artifacts'
    'ti backup list ~/Desktop' 'ti backup restore ' 'ti help backup'
    'ti data load ' 'ti data load big.csv --name logs' 'ti data load capture.pcap' 'ti data load history.xml --name http' 'ti data load notes.bak' 'ti data list' 'ti data show dt1' 'ti help data'
  )
  typeset -A TACU_GHOST_NEXT TACU_GHOST_ENUM
  TACU_GHOST_NEXT=(
    'ti tools' ' map'
    'ti tools ' 'map'
    'ti tools run' ' process'
    'ti tools run ' 'process'
    'ti tools run process' ' --input {"operation":"top_cpu","limit":10}'
    'ti tools run network' ' --input {"operation":"connections","state":"ESTABLISHED"}'
    'ti tools map' ' . --depth 3'
    'ti tools map ' '. --depth 3'
    'ti tools map .' ' --depth 3'
    'ti tools find' ' "*.yaml" .'
    'ti tools find ' '"*.yaml" .'
    'ti tools search' ' TODO .'
    'ti tools search ' 'TODO .'
    'ti tools read' ' README.md --start 1 --end 80'
    'ti tools read ' 'README.md --start 1 --end 80'
    'ti tools describe' ' process'
    'ti tools describe ' 'process'
    'ti config' ' show'
    'ti config ' 'show'
    'ti config update' ' --model '
    'ti config update ' '--model '
    'ti config update --model' ' gemma4:12b-mlx --context-turns 5'
    'ti config update --model ' 'gemma4:12b-mlx --context-turns 5'
    'ti model' ' use '
    'ti model ' 'use '
    'ti model use' ' gemma4:12b-mlx'
    'ti model use ' 'gemma4:12b-mlx'
    'ti workspace' ' show'
    'ti workspace ' 'show'
    'ti workspace use' ' '
    'ti workspace create' ' '
    'ti extract' ' juicy '
    'ti extract ' 'juicy '
    'ti extract juicy' ' '
    'ti juicy' ' '
    'ti help' ' '
    'ti data' ' load'
    'ti data ' 'load'
    'ti data list' ' '
    'ti backup' ' create'
    'ti backup ' 'create'
    'ti backup create' ' ~/Desktop'
    'ti backup create ' '~/Desktop'
    'ti backup list' ' ~/Desktop'
    'ti backup list ' '~/Desktop'
    'ti backup restore' ' '
    'ti clip' ' list'
    'ti clip ' 'list'
    'ti clip add' ' "'
    'ti clip add --from-turn' ' 42:3'
    'ti clip show' ' 3'
    'ti clip rm' ' 3'
    'ti clip clear' ' --yes'
    'ti review' ' search '
    'ti review ' 'search '
    'ti history' ' search '
    'ti syntax' ' search '
    'ti syntax ' 'search '
    'ti syntax search' ' cpu'
    'ti save' ' 42 --format md'
    'ti save 42' ' --format md'
    'ti save 42 --format' ' md'
    'ti copy' ' last'
    'ti copy ' 'last'
    'ti copy last' ':1'
    'ti copy last:1' ' --to-clip'
    'ti copy 42' ':3'
    'ti copy 42:3' ' --to-clip'
    'ti inspect' ' -- '
    'ti inspect --' ' '
    'ti run' ' -q '
    'ti run ' '-q '
    'ti ask' ' '
    'ti auto' ' '
    'ti do' ' '
    'ti web' ' '
  )
  # L2 enums  # L2 enums after specific flags
  TACU_GHOST_ENUM=(
    '--format ' 'md'
    '--type ' 'file'
    '--depth ' '3'
    '--context-turns ' '5'
  )
  typeset -g TACU_GHOST_ASYNC_PID=0 TACU_GHOST_ASYNC_KEY=''
  # After Esc, keep ghost clear until BUFFER changes (reset-prompt must not refill it).
  typeset -g TACU_GHOST_SUPPRESS_KEY=''
  typeset -g TACU_GHOST_LAST_KEY=''

  _tacu_ghost_unique_prefix() {
    # $1 = needle, remaining argv = candidates → print unique completion suffix or empty
    local needle="$1" match="" count=0 candidate
    shift
    for candidate in "$@"; do
      [[ "$candidate" == "$needle"* ]] || continue
      (( count++ ))
      match="$candidate"
      (( count > 1 )) && { print -r -- ''; return 0 }
    done
    (( count == 1 )) && print -r -- "${match#$needle}" || print -r -- ''
  }

  _tacu_ghost_structural() {
    # L1/L2: deterministic next token from grammar — never a long NL phrase.
    # Incomplete unique prefixes return the rest of the token; exact tokens fall
    # through to TACU_GHOST_NEXT so "ti tools map" still ghosts " . --depth 3".
    local key="$1" rest suffix
    if [[ "$key" == ti ]]; then
      print -r -- ' '
      return
    fi
    if [[ "$key" == ti\  ]]; then
      print -r -- ''
      return
    fi
    if [[ "$key" =~ '^ti ([a-z][a-z0-9-]*)$' ]]; then
      suffix="$(_tacu_ghost_unique_prefix "$match[1]" $TACU_GHOST_COMMANDS)"
      if [[ -n "$suffix" ]]; then
        print -r -- "$suffix"
        return
      fi
    fi
    if [[ "$key" =~ '^ti tools ([a-z]*)$' ]]; then
      suffix="$(_tacu_ghost_unique_prefix "$match[1]" $TACU_GHOST_TOOL_ACTIONS)"
      if [[ -n "$suffix" ]]; then
        print -r -- "$suffix"
        return
      fi
    fi
    if [[ "$key" =~ '^ti help ([a-z]*)$' ]]; then
      suffix="$(_tacu_ghost_unique_prefix "$match[1]" $TACU_GHOST_HELP_TOPICS)"
      if [[ -n "$suffix" ]]; then
        print -r -- "$suffix"
        return
      fi
    fi
    if [[ "$key" =~ '^ti backup ([a-z]*)$' ]]; then
      suffix="$(_tacu_ghost_unique_prefix "$match[1]" $TACU_GHOST_BACKUP_ACTIONS)"
      if [[ -n "$suffix" ]]; then
        print -r -- "$suffix"
        return
      fi
    fi
    if [[ "$key" =~ '^ti data ([a-z]*)$' ]]; then
      suffix="$(_tacu_ghost_unique_prefix "$match[1]" $TACU_GHOST_DATA_ACTIONS)"
      if [[ -n "$suffix" ]]; then
        print -r -- "$suffix"
        return
      fi
    fi
    # Grammar defaults for non-intent commands (tools/config/clip/…)
    if (( ${+TACU_GHOST_NEXT[$key]} )); then
      rest="${TACU_GHOST_NEXT[$key]}"
      case "$key" in
        ti\ ask*|ti\ auto*|ti\ do*|ti\ web*|ti\ run\ -q*)
          ;;
        *)
          print -r -- "$rest"
          return
          ;;
      esac
    fi
    # Flag enums: … --format␠ → md
    for flag val in ${(kv)TACU_GHOST_ENUM}; do
      if [[ "$key" == *"$flag" && -z "${key##*$flag}" ]]; then
        print -r -- "$val"
        return
      fi
    done
    print -r -- ''
  }

  _tacu_ghost_insertable() {
    # A ghost suggestion is typed into the user's command line for them, so it
    # must be text they can read and edit. History can hold a line saved in a
    # broken encoding — one mangled Devanagari command in ~/.zsh_history was
    # replayed into the prompt every time "ti auto " was typed, which looked
    # like TACU emitting Hindi out of nowhere. Suggest ASCII only.
    [[ "$1" != *[^[:ascii:]]* ]]
  }

  _tacu_ghost_from_history() {
    # L3: successful TACU cmds (ghost_cmds.log) + zsh history — frequency/recency/cwd.
    local key="$1" line cmd row_cwd stamp suffix
    local -A scores
    local log="${TACU_HOME:-$HOME/.local/share/tacu}/ghost_cmds.log"
    local here="$PWD"
    if [[ -f "$log" ]]; then
      while IFS=$'\t' read -r stamp row_cwd cmd; do
        [[ "$cmd" == "$key"* && "$cmd" != "$key" ]] || continue
        _tacu_ghost_insertable "$cmd" || continue
        local bonus=1
        [[ "$row_cwd" == "$here" ]] && bonus=2
        scores[$cmd]=$(( ${scores[$cmd]:-0} + bonus ))
      done < "$log"
    fi
    if (( ${#scores} )); then
      local best="" best_score=0
      for cmd in ${(k)scores}; do
        if (( scores[$cmd] >= best_score )); then
          best_score=${scores[$cmd]}
          best=$cmd
        fi
      done
      if [[ -n "$best" ]]; then
        print -r -- "${best#$key}"
        return
      fi
    fi
    for line in ${(Oa)history}; do
      [[ "$line" == ti\ * || "$line" == ticu\ * ]] || continue
      [[ "$line" == ticu* ]] && line="ti${line#ticu}"
      _tacu_ghost_insertable "$line" || continue
      if [[ "$line" == "$key"* && "$line" != "$key" ]]; then
        print -r -- "${line#$key}"
        return
      fi
    done
    print -r -- ''
  }

  _tacu_ghost_semantic_ok() {
    # L4 only for free-text intent regions (low structural confidence).
    local key="$1"
    [[ "$key" == ti\ ask* || "$key" == ti\ auto* || "$key" == ti\ do* || "$key" == ti\ web* ]] && return 0
    [[ "$key" == ti\ run\ -q* || "$key" == ti\ run\ --shell* ]] && return 0
    # Mid-phrase after a known short structural token was already handled.
    [[ "$key" == ti\ *\ * && "$key" != ti\ tools* && "$key" != ti\ help* && "$key" != ti\ config* && "$key" != ti\ model* && "$key" != ti\ clip* && "$key" != ti\ syntax* && "$key" != ti\ review* && "$key" != ti\ copy* && "$key" != ti\ save* ]] && return 0
    return 1
  }

  _tacu_ghost_semantic() {
    local key="$1" candidate
    if (( ${+TACU_GHOST_NEXT[$key]} )); then
      print -r -- "${TACU_GHOST_NEXT[$key]}"
      return
    fi
    for candidate in $TACU_GHOST_EXAMPLES; do
      if [[ "$candidate" == "$key"* && "$candidate" != "$key" ]]; then
        print -r -- "${candidate#$key}"
        return
      fi
    done
    print -r -- ''
  }

  _tacu_ghost_model_async() {
    # L5: opt-in, debounced, never blocks the keystroke path.
    [[ "${TACU_GHOST_MODEL:-0}" == 1 ]] || return
    local key="$1" cache="${TMPDIR:-/tmp}/tacu-ghost-$$.suggest"
    (( TACU_GHOST_ASYNC_PID )) && kill $TACU_GHOST_ASYNC_PID 2>/dev/null
    TACU_GHOST_ASYNC_KEY="$key"
    (
      sleep 0.35
      command ti __ghost-suggest --model -- "$key" >|"$cache" 2>/dev/null
    ) &!
    TACU_GHOST_ASYNC_PID=$!
    if [[ -f "$cache" ]]; then
      local line
      line="$(<"$cache")"
      if [[ -n "$line" && "$line" == "$key"* && "$line" != "$key" ]]; then
        print -r -- "${line#$key}"
        return
      fi
    fi
    print -r -- ''
  }

  _tacu_ghost_refresh() {
    local key="$BUFFER" suffix=''
    [[ "$key" == ti* || "$key" == ticu* ]] || { TACU_GHOST_SUPPRESS_KEY=''; TACU_GHOST_LAST_KEY=''; POSTDISPLAY=''; return }
    # line-pre-redraw fires constantly; do not rescan history on an unchanged line.
    if [[ -n "$TACU_GHOST_LAST_KEY" && "$key" == "$TACU_GHOST_LAST_KEY" ]]; then
      return
    fi
    TACU_GHOST_LAST_KEY="$key"
    POSTDISPLAY=''
    # Esc suppress: do not refill until the user edits the line.
    if [[ -n "$TACU_GHOST_SUPPRESS_KEY" ]]; then
      if [[ "$BUFFER" == "$TACU_GHOST_SUPPRESS_KEY" ]]; then
        return
      fi
      TACU_GHOST_SUPPRESS_KEY=''
    fi
    [[ "$key" == ticu* ]] && key="ti${key#ticu}"

    # Layer 1–2: structural / grammar (instant, high confidence)
    suffix="$(_tacu_ghost_structural "$key")"
    if [[ -n "$suffix" ]]; then
      POSTDISPLAY="$suffix"
      return
    fi

    # Layer 3: history (successful cmds + shell history)
    suffix="$(_tacu_ghost_from_history "$key")"
    if [[ -n "$suffix" ]]; then
      POSTDISPLAY="$suffix"
      return
    fi

    # Layer 4: semantic curated ghosts (only when free-text / low confidence)
    if _tacu_ghost_semantic_ok "$key"; then
      suffix="$(_tacu_ghost_semantic "$key")"
      if [[ -n "$suffix" ]]; then
        POSTDISPLAY="$suffix"
        return
      fi
    fi

    # Layer 5: async model (opt-in; may populate on a later redraw)
    suffix="$(_tacu_ghost_model_async "$key")"
    [[ -n "$suffix" ]] && POSTDISPLAY="$suffix"
  }

  _tacu_accept_ghost() {
    if [[ $CURSOR -eq ${#BUFFER} && -n "$POSTDISPLAY" ]]; then
      LBUFFER+="$POSTDISPLAY"
      POSTDISPLAY=''
      TACU_GHOST_SUPPRESS_KEY=''
      zle -R
    else
      zle .forward-char
    fi
  }
  _tacu_accept_ghost_end() {
    if [[ -n "$POSTDISPLAY" ]]; then
      LBUFFER+="$POSTDISPLAY"
      POSTDISPLAY=''
      TACU_GHOST_SUPPRESS_KEY=''
      zle -R
    else
      zle .end-of-line
    fi
  }
  _tacu_reject_ghost() {
    # Esc clears the dim ghost without changing typed text.
    # Suppress refill on the redraw that follows Escape.
    if [[ -n "$POSTDISPLAY" ]]; then
      POSTDISPLAY=''
      TACU_GHOST_SUPPRESS_KEY="$BUFFER"
      zle -R
      return 0
    fi
  }
  _tacu_tab_complete() {
    # Tab always runs real completion (short names only). Never accepts a ghost phrase.
    POSTDISPLAY=''
    TACU_GHOST_SUPPRESS_KEY="$BUFFER"
    zle expand-or-complete
  }
  zle -N _tacu_accept_ghost
  zle -N _tacu_accept_ghost_end
  zle -N _tacu_reject_ghost
  zle -N _tacu_tab_complete
  add-zle-hook-widget line-pre-redraw _tacu_ghost_refresh
  # Dim ghost: 256-color grey (Apple Terminal often paints fg=8 as normal text).
  zle_highlight=(${zle_highlight:#suffix:*})
  zle_highlight+=(suffix:fg=244)
  # Keys: Tab=complete · →/End/Ctrl-E=accept · Esc=reject
  bindkey -M emacs '^I' _tacu_tab_complete
  bindkey -M viins '^I' _tacu_tab_complete
  bindkey '^I' _tacu_tab_complete
  bindkey -M emacs '^[[C' _tacu_accept_ghost
  bindkey -M viins '^[[C' _tacu_accept_ghost
  bindkey '^[[C' _tacu_accept_ghost
  bindkey -M emacs '^E' _tacu_accept_ghost_end
  bindkey '^E' _tacu_accept_ghost_end
  bindkey '^[[F' _tacu_accept_ghost_end
  bindkey -M emacs '^[' _tacu_reject_ghost
  bindkey -M viins '^[' _tacu_reject_ghost
  bindkey '^[' _tacu_reject_ghost
fi
'''



def bash_completion() -> str:
    return f'''_tacu_complete() {{
  local current previous
  current="${{COMP_WORDS[COMP_CWORD]}}"
  previous="${{COMP_WORDS[COMP_CWORD-1]}}"
  local commands="{COMMANDS}"
  local tool_actions="{TOOL_ACTIONS}"
  local tools="{TOOLS}"
  if [[ $COMP_CWORD -eq 1 ]]; then COMPREPLY=( $(compgen -W "$commands" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "$tool_actions" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ( ${{COMP_WORDS[2]}} == describe || ${{COMP_WORDS[2]}} == run ) && $COMP_CWORD -eq 3 ]]; then COMPREPLY=( $(compgen -W "$tools" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == run && $COMP_CWORD -ge 4 ]]; then COMPREPLY=( $(compgen -W "--input --workspace --approve" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == config && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "show update reset" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == config && ${{COMP_WORDS[2]}} == update ]]; then COMPREPLY=( $(compgen -W "--model --context-turns" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == model && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "current list use reset" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == workspace && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "show enter create use" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == map ]]; then COMPREPLY=( $(compgen -W "--depth --symbols --max-files --json" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == find ]]; then COMPREPLY=( $(compgen -W "--type --case-sensitive --case-insensitive --max-results --json" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == search ]]; then COMPREPLY=( $(compgen -W "--regex --case-sensitive --case-insensitive --glob --max-results --json" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == read ]]; then
    if [[ $current == -* ]]; then COMPREPLY=( $(compgen -W "--start --end --json" -- "$current") ); else COMPREPLY=( $(compgen -f -- "$current") ); fi
    return
  fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == write ]]; then
    if [[ $current == -* ]]; then COMPREPLY=( $(compgen -W "--content --overwrite --json" -- "$current") ); else COMPREPLY=( $(compgen -f -- "$current") ); fi
    return
  fi
  if [[ ${{COMP_WORDS[1]}} == tools && ${{COMP_WORDS[2]}} == edit ]]; then
    if [[ $current == -* ]]; then COMPREPLY=( $(compgen -W "--old --new --expected-count --json" -- "$current") ); else COMPREPLY=( $(compgen -f -- "$current") ); fi
    return
  fi
  if [[ ${{COMP_WORDS[1]}} == help && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "{HELP_TOPICS}" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == syntax ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "list search show seed add rm clear" -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == clear ]]; then COMPREPLY=( $(compgen -W "--yes" -- "$current") ); return; fi
  fi
  if [[ ${{COMP_WORDS[1]}} == copy ]]; then COMPREPLY=( $(compgen -W "last --block --command --to-clip --label" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == history || ${{COMP_WORDS[1]}} == menu || ${{COMP_WORDS[1]}} == review || ${{COMP_WORDS[1]}} == report ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "list search find --list" -- "$current") ); return; fi
  fi
  if [[ ${{COMP_WORDS[1]}} == clip || ${{COMP_WORDS[1]}} == tray ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "list status add show edit rm search clear copy" -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == clear ]]; then COMPREPLY=( $(compgen -W "--yes" -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == add || ${{COMP_WORDS[2]}} == edit ]]; then COMPREPLY=( $(compgen -W "--label --from-turn --block" -- "$current") ); return; fi
  fi
  if [[ ${{COMP_WORDS[1]}} == data || ${{COMP_WORDS[1]}} == dataset ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "{DATA_ACTIONS}" -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == load ]]; then COMPREPLY=( $(compgen -W "--name --ttl --delimiter --header --no-header" -f -- "$current") ); return; fi
    COMPREPLY=( $(compgen -W "$(command ticu __data-names 2>/dev/null)" -- "$current") ); return
  fi
  if [[ ${{COMP_WORDS[1]}} == backup ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "{BACKUP_ACTIONS}" -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == create ]]; then COMPREPLY=( $(compgen -W "--include-artifacts" -f -- "$current") ); return; fi
    if [[ ${{COMP_WORDS[2]}} == restore ]]; then COMPREPLY=( $(compgen -W "--merge --yes --no-safety-copy" -f -- "$current") ); return; fi
    COMPREPLY=( $(compgen -f -- "$current") ); return
  fi
  if [[ ${{COMP_WORDS[1]}} == extract && $COMP_CWORD -eq 2 ]]; then COMPREPLY=( $(compgen -W "juicy" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == juicy ]]; then COMPREPLY=( $(compgen -W "--ask --format --min-confidence --kind --grep -o --output --turn --reports --resume --all-files" -f -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == ask || ${{COMP_WORDS[1]}} == analyze ]]; then COMPREPLY=( $(compgen -W "--keys --cols --path --grep --head --tail --limit --no-ai" -- "$current") ); return; fi
  if [[ ${{COMP_WORDS[1]}} == auto || ${{COMP_WORDS[1]}} == do ]]; then COMPREPLY=( $(compgen -W "--dry-run --workspace --max-steps" -- "$current") ); return; fi
  COMPREPLY=( $(compgen -f -- "$current") )
}}
complete -F _tacu_complete ticu ti
'''


def fish_completion() -> str:
    commands = " ".join(COMMANDS.split())
    return f'''complete -c ticu -f -n '__fish_use_subcommand' -a '{commands}'
complete -c ti -f -n '__fish_use_subcommand' -a '{commands}'
complete -c ticu -n '__fish_seen_subcommand_from tools' -a '{TOOL_ACTIONS}'
complete -c ti -n '__fish_seen_subcommand_from tools' -a '{TOOL_ACTIONS}'
complete -c ticu -n '__fish_seen_subcommand_from describe run' -a '{TOOLS}'
complete -c ti -n '__fish_seen_subcommand_from describe run' -a '{TOOLS}'
complete -c ticu -n '__fish_seen_subcommand_from run' -l input -l workspace -l approve
complete -c ti -n '__fish_seen_subcommand_from run' -l input -l workspace -l approve
complete -c ticu -n '__fish_seen_subcommand_from config' -a 'show update reset'
complete -c ti -n '__fish_seen_subcommand_from config' -a 'show update reset'
complete -c ticu -n '__fish_seen_subcommand_from model' -a 'current list use reset'
complete -c ti -n '__fish_seen_subcommand_from model' -a 'current list use reset'
complete -c ticu -n '__fish_seen_subcommand_from workspace' -a 'show enter create use'
complete -c ti -n '__fish_seen_subcommand_from workspace' -a 'show enter create use'
complete -c ticu -n '__fish_seen_subcommand_from map' -l depth -l symbols -l max-files -l json
complete -c ti -n '__fish_seen_subcommand_from map' -l depth -l symbols -l max-files -l json
complete -c ticu -n '__fish_seen_subcommand_from find' -l type -l case-sensitive -l case-insensitive -l max-results -l json
complete -c ti -n '__fish_seen_subcommand_from find' -l type -l case-sensitive -l case-insensitive -l max-results -l json
complete -c ticu -n '__fish_seen_subcommand_from write' -l content -l overwrite -l json
complete -c ti -n '__fish_seen_subcommand_from write' -l content -l overwrite -l json
complete -c ticu -n '__fish_seen_subcommand_from edit' -l old -l new -l expected-count -l json
complete -c ti -n '__fish_seen_subcommand_from edit' -l old -l new -l expected-count -l json
complete -c ticu -n '__fish_seen_subcommand_from extract' -a 'juicy'
complete -c ti -n '__fish_seen_subcommand_from extract' -a 'juicy'
complete -c ticu -n '__fish_seen_subcommand_from ask analyze' -l keys -l cols -l path -l grep -l head -l tail -l limit -l no-ai
complete -c ti -n '__fish_seen_subcommand_from ask analyze' -l keys -l cols -l path -l grep -l head -l tail -l limit -l no-ai
complete -c ticu -n '__fish_seen_subcommand_from auto do' -l dry-run -l workspace -l max-steps
complete -c ti -n '__fish_seen_subcommand_from auto do' -l dry-run -l workspace -l max-steps
complete -c ticu -n '__fish_seen_subcommand_from help' -a '{HELP_TOPICS}'
complete -c ti -n '__fish_seen_subcommand_from help' -a '{HELP_TOPICS}'
complete -c ticu -n '__fish_seen_subcommand_from history menu review report' -a 'list search find'
complete -c ti -n '__fish_seen_subcommand_from history menu review report' -a 'list search find'
complete -c ticu -n '__fish_seen_subcommand_from history menu review report' -l list
complete -c ti -n '__fish_seen_subcommand_from history menu review report' -l list
complete -c ticu -n '__fish_seen_subcommand_from syntax' -a 'list search show seed add rm clear'
complete -c ti -n '__fish_seen_subcommand_from syntax' -a 'list search show seed add rm clear'
complete -c ticu -n '__fish_seen_subcommand_from clip tray' -a 'list status add show edit rm search clear copy'
complete -c ti -n '__fish_seen_subcommand_from clip tray' -a 'list status add show edit rm search clear copy'
complete -c ticu -n '__fish_seen_subcommand_from copy' -a last -d 'latest answer'
complete -c ti -n '__fish_seen_subcommand_from copy' -a last -d 'latest answer'
complete -c ticu -n '__fish_seen_subcommand_from copy' -l block -l command -l to-clip -l label
complete -c ti -n '__fish_seen_subcommand_from copy' -l block -l command -l to-clip -l label
complete -c ticu -n '__fish_seen_subcommand_from clear' -l yes
complete -c ti -n '__fish_seen_subcommand_from clear' -l yes
complete -c ticu -n '__fish_seen_subcommand_from backup' -a '{BACKUP_ACTIONS}'
complete -c ti -n '__fish_seen_subcommand_from backup' -a '{BACKUP_ACTIONS}'
complete -c ticu -n '__fish_seen_subcommand_from data dataset' -a '{DATA_ACTIONS}'
complete -c ti -n '__fish_seen_subcommand_from data dataset' -a '{DATA_ACTIONS}'
complete -c ticu -n '__fish_seen_subcommand_from create' -l include-artifacts
complete -c ti -n '__fish_seen_subcommand_from create' -l include-artifacts
complete -c ticu -n '__fish_seen_subcommand_from restore' -l merge -l yes -l no-safety-copy
complete -c ti -n '__fish_seen_subcommand_from restore' -l merge -l yes -l no-safety-copy
'''


def powershell_completion() -> str:
    return f'''$TicuCommands = @('{"','".join(COMMANDS.split())}')
$TicuTools = @('{"','".join(TOOLS.split())}')
$TicuToolActions = @('{"','".join(TOOL_ACTIONS.split())}')
$TacuCompleter = {{ param($wordToComplete, $commandAst, $cursorPosition)
  $elements = @($commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }})
  $values = if ($elements.Count -ge 2 -and $elements[1] -eq 'tools') {{
    if ($elements.Count -ge 3 -and $elements[2] -in @('describe','run')) {{ $TicuTools }} else {{ $TicuToolActions }}
  }} else {{ $TicuCommands }}
  $values | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }}
}}
Register-ArgumentCompleter -Native -CommandName ticu,ti -ScriptBlock $TacuCompleter
'''


def completion_script(shell: str = "auto") -> str:
    selected = detect_shell() if shell == "auto" else shell.casefold()
    generators = {"zsh": zsh_completion, "bash": bash_completion, "fish": fish_completion,
                  "powershell": powershell_completion, "pwsh": powershell_completion}
    generator = generators.get(selected)
    if not generator:
        raise TacuError(f"Unsupported shell: {selected}. Choose zsh, bash, fish, or powershell.")
    return generator()


def shell_initialization(shell: str = "auto") -> str:
    selected = detect_shell() if shell == "auto" else shell.casefold()
    completion = completion_script(selected)
    if selected == "zsh":
        return "\n".join((
            "alias ticu='noglob ticu'", "alias ti='noglob ti'",
            "export TACU_SHELL_INTEGRATION=1",
            "setopt complete_aliases",
            # Esc alone rejects ghost; keep arrow sequences intact.
            "KEYTIMEOUT=${KEYTIMEOUT:-20}",
            "autoload -Uz compinit",
            "compinit -C 2>/dev/null || compinit",
            "zstyle ':completion:*' menu select",
            "zstyle ':completion:*' verbose yes",
            "zstyle ':completion:*' list-colors ''",
            "zstyle ':completion:*:descriptions' format '%F{244}-- %d --%f'",
            "zstyle ':completion:*:messages' format '%F{244}%d%f'",
            "zstyle ':completion:*:warnings' format '%F{244}no matches%f'",
            completion,
            zsh_ghost(),
            "compdef _tacu ticu ti",
        ))
    if selected == "powershell":
        return completion + "\nSet-PSReadLineOption -PredictionSource History -ErrorAction SilentlyContinue\n"
    return completion
