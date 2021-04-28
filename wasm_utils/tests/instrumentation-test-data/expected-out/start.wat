(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param f32)))
  (type (;3;) (func (param i32 i32) (result i32)))
  (type (;4;) (func (param i64)))
  (type (;5;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  (import "__" "update_available_memory" (func (;1;) (type 3)))
  (import "foo" "bar" (func (;2;) (type 1)))
  (import "foo" "bar" (func (;3;) (type 2)))
  (func (;4;) (type 1))
  (func (;5;) (type 1)
    global.get 0
    i64.const 2
    i64.sub
    global.set 0
    global.get 0
    i64.const 0
    i64.lt_s
    if  ;; label = @1
      call 0
    end
    i32.const 42
    drop)
  (func (;6;) (type 4) (param i64)
    local.get 0
    global.set 0)
  (func (;7;) (type 5) (result i64)
    global.get 0)
  (table (;0;) 0 1 funcref)
  (memory (;0;) 1 1)
  (global (;0;) (mut i64) (i64.const 0))
  (export "e" (func 3))
  (export "table" (table 0))
  (export "memory" (memory 0))
  (export "canister counter_set" (func 6))
  (export "canister counter_get" (func 7))
  (export "canister counter_instructions" (global 0))
  (export "canister_start" (func 2)))
