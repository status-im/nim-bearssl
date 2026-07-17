import ./[csources]

{.used.}

# Conflicing static inlines -> one unit per size
{.compile: currentSourceDir & "/i15.c".}
{.compile: currentSourceDir & "/i31.c".}
{.compile: currentSourceDir & "/i32.c".}
{.compile: currentSourceDir & "/i62.c".}
