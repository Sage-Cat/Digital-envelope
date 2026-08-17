# Third-party notices

This repository links to, but does not vendor, the following pinned Git submodules. Their own license files remain authoritative.

- [Qt-Secret](https://github.com/QuasarApp/Qt-Secret) at `8b44c00121469941f66689cdb89aad2db2d3681a` — GNU LGPL v3.0. It supplies the educational RSA implementation.
- [Qt-AES](https://github.com/QuasarApp/Qt-AES) at `86811dd24f00335c5dffa4949a622542ed70c377` — Unlicense. It is a transitive Qt-Secret submodule and is built into the Qt-Secret library, although this application does not call its AES API.
- [mini-gmp](https://github.com/QuasarApp/mini-gmp) at `7281435f64aeba21395d852c935a5c0cf58a564a` — MIT License. It supplies big-integer support to Qt-Secret.
- Qt 5 — available under the terms published by [The Qt Company](https://www.qt.io/licensing/open-source-lgpl-obligations), including LGPL options for applicable modules. This project uses Qt Core, GUI, and Widgets.

Qt-Secret and its transitive dependencies are fetched only by `git submodule update --init --recursive`; this repository records their commits and does not relicense their code.
