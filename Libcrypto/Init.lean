/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

namespace Libcrypto

@[extern "lc_initialize"]
private opaque registerExternalClasses : IO Unit

initialize registerExternalClasses

end Libcrypto
