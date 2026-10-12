# AEGIS landing page

The front page of the unified AEGIS repository. **AEGIS** means **Android Evidence & Git Inspection System**.

The hub at `/` introduces the product capabilities and opens the three operating workspaces:

| Entry | Workspace |
|---|---|
| APKTrust — Android Security | `/android/` |
| RepoSentinel — Repository Security | `/repository/` |
| FileSentinel — File & Binary Investigation | `/file/` |

The full-screen introduction runs on each root visit/reload for about 6.8 seconds. It has Skip and reduced-motion behavior. Its percentage represents the welcome animation, never scan progress.

## Run and edit

Follow the [root setup](../README.md#quick-start) and run `./start.sh` from the repository root. Open http://127.0.0.1:8797/.

`index.html`, `style.css` and `app.js` are served by the gateway without a frontend build step. Shared icons, theme and font live in `../shared/`. Preserve the common blue palette when changing either workspace.

This page does not scan files, store reports or configure providers. Those functions belong to the three workspaces. The hub and modules ship in this same repository.
