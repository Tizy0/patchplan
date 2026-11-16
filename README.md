# Patch Plan Editor

Stage cable / patch plan editor in a single HTML file (`patchplan.html`).

- `patchplan.html` – the program (source of truth)
- `milestones/patchplan_vN.html` – snapshot of every build
- `public/` – what the website serves (`index.html` is copied from `patchplan.html` by `npm run build`)

## Publish the website

    npm install
    npm run deploy      # copies patchplan.html -> public/index.html and uploads it to Cloudflare

The build number is in `patchplan.html` (`const BUILD`), with the change log in `BUILD_NOTES`.
