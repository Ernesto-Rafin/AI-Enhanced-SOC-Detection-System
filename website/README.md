# Ernesto Rafin — Personal Website

A static, dependency-free personal site (`index.html` + `assets/`). Light and dark themes, responsive down to phone width, print-friendly, with SEO and Schema.org `Person` metadata.

## Deploy on GitHub Pages (recommended URL: `https://ernesto-rafin.github.io`)

1. Create a new public repository named exactly **`Ernesto-Rafin.github.io`**.
2. Copy the contents of this `website/` folder (`index.html`, `assets/`, `.nojekyll`) to the root of that repository and push.
3. In the repository, open **Settings → Pages**, set *Source* to **Deploy from a branch**, branch `main`, folder `/ (root)`.
4. The site goes live at `https://ernesto-rafin.github.io` within a minute or two.

After it is live, add the URL to your LinkedIn "Website" field, your GitHub profile, your Google Scholar homepage, and your resume header.

## Updating content

Everything lives in `index.html`. Sections are clearly marked with comments (`HERO`, `NEWS`, `RESEARCH`, `PUBLICATIONS`, …). To add a news item, copy one `<li>` in the `news` list. To replace the photo, overwrite `assets/ernesto-rafin.jpg` with a 3:4 portrait.
