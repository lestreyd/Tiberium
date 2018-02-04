
Debian
====================
This directory contains files used to package Tiberiumd/Tiberium-qt
for Debian-based Linux systems. If you compile Tiberiumd/Tiberium-qt yourself, there are some useful files here.

## Tiberium: URI support ##


Tiberium-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install Tiberium-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your Tiberiumqt binary to `/usr/bin`
and the `../../share/pixmaps/Tiberium128.png` to `/usr/share/pixmaps`

Tiberium-qt.protocol (KDE)

