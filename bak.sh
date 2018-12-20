#!/bin/sh
mkdir -p backups
cp app.db backups/$(date '+%Y%m%d%H%M%S').db
