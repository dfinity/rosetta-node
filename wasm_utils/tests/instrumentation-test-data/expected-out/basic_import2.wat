(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 2)))
  (import "__" "update_available_memory" (func (;1;) (type 0)))
  (import "foo" "meter" (func (;2;) (type 1)))
  (func (;3;) (type 0) (param i32 i32) (result i32)
    global.get 0
    i64.const 3
    i64.sub
    global.set 0
    global.get 0
    i64.const 0
    i64.lt_s
    if  ;; label = @1
      call 0
    end
    local.get 0
    local.get 1
    i32.add)
  (func (;4;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;5;) (type 4) (result i64)
    global.get 0)
  (global (;0;) (mut i64) (i64.const 0))
  (export "addTwo" (func 3))
  (export "canister counter_set" (func 4))
  (export "canister counter_get" (func 5))
  (export "canister counter_instructions" (global 0)))
