#!/bin/bash

DOCS_DIR=docs

# exit when any command fails
set -e

# Move typedoc documentation to the packages dir
rm -rf $DOCS_DIR/packages
mkdir -p $DOCS_DIR/packages
for PACKAGE_DIR in packages/* ; do
    if [ -d "$PACKAGE_DIR/typedocs" ] 
    then
        echo "Copying typedocs of $PACKAGE_DIR "
        cp -r $PACKAGE_DIR/typedocs $DOCS_DIR/$PACKAGE_DIR
    else
        echo "No typedocs, ignoring $PACKAGE_DIR, "
    fi
    
done

# Move autogenerated reference
mkdir -p $DOCS_DIR/reference
mv packages/cli/docs/cli.md $DOCS_DIR/reference/cli.md

# Copy contributing doc
cp CONTRIBUTING.md $DOCS_DIR/contributing.md

# Copy visual assets
rm -rf $DOCS_DIR/assets
cp -r assets $DOCS_DIR/assets