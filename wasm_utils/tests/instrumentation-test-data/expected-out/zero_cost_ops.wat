(module
  (type (;0;) (func (param i64) (result i64)))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  (import "__" "update_available_memory" (func (;1;) (type 2)))
  (func (;2;) (type 0) (param i64) (result i64)
    global.get 0
    i64.const 4
    i64.sub
    global.set 0
    global.get 0
    i64.const 0
    i64.lt_s
    if  ;; label = @1
      call 0
    end
    local.get 0
    i64.const 1
    i64.lt_s
    if (result i64)  ;; label = @1
      global.get 0
      i64.const 1
      i64.sub
      global.set 0
      i64.const 1
    else
      global.get 0
      i64.const 6
      i64.sub
      global.set 0
      local.get 0
      local.get 0
      i64.const 1
      i64.sub
      call 2
      i64.mul
    end)
  (func (;3;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;4;) (type 4) (result i64)
    global.get 0)
  (global (;0;) (mut i64) (i64.const 0))
  (export "fac" (func 2))
  (export "canister counter_set" (func 3))
  (export "canister counter_get" (func 4))
  (export "canister counter_instructions" (global 0)))
