# Test the full thing, given we do lots of compile and import tricks

import ../bearssl

discard getConfig()

# TODO doesn't work from C++ due to `const`:ness issues
# discard ecGetDefault()

discard ghashPwr8Get()
