# cbth Agent Delivery Contract

## Current Skill Contract

Skills may use `cbth` for long-running tests, CI waits, review lanes, and other background tasks. Treat it as a task supervision and delivery substrate, not as the workflow brain.

Required behavior for agents:

- Resolve `source_thread_id` from `CODEX_THREAD_ID` by default.
- If `CODEX_THREAD_ID` is missing, require an explicit source thread id instead of guessing from recent sessions.
- After submitting a task, immediately print the recovery block to the user and persist the same block in a task-scoped note or receipt artifact.
- The recovery block must include `source_thread_id`, `task_id`, `job_id`, the expected way to discover `batch_id`, and read-only inspect commands.
- Synchronous waiting means polling/awaiting task state only. It must not consume or close delivery.
- If the agent stops waiting early, async delivery must remain available.
- Current automatic async delivery is idle-only `turn/start`. Do not depend on `turn/steer`.

Useful current commands:

- `cbth task run --source-thread-id <thread-id> --summary <summary> --cwd <cwd> --timeout-seconds <seconds> -- <command> ...`
- `cbth task inspect --task-id <task-id>`
- `cbth task list --source-thread-id <thread-id>`
- `cbth job inspect --job-id <job-id>`
- `cbth batch inspect-head --source-thread-id <thread-id>`
- `cbth audit list --source-thread-id <thread-id> --limit 50`
- `cbth doctor cli`
- `cbth daemon status`

## Follow-Up Plan For cbth

These are required before skills can safely treat background delivery as fully agent-recoverable:

- Add a durable receipt view queryable by `source_thread_id`, `task_id`, `job_id`, and `batch_id`.
- Add agent-facing inspect/summary commands that reconstruct recovery commands after restart, compact, or shell history loss.
- Add ergonomic `job -> batch` lookup so agents do not need sqlite joins or indirect audit mining.
- Model `await` as a lease. Lease expiry or caller interruption must leave async delivery intact.
- Model `consume` as two phases: `consume_pending`, then `caller_consumed` only after cbth proves the caller turn completed or an equivalent durable visible receipt exists.
- Keep `turn/start` as the active automatic delivery driver.
- Enable `turn/steer` only after cbth can prove active turn id, managed session id, session epoch, low-risk class, accepted turn lifecycle, and terminal observation. Agents must not provide trusted `active_turn_id`.
