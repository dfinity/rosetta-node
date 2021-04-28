(module
  (type (;0;) (func))
  (type (;1;) (func (result i32)))
  (type (;2;) (func (param i32) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32) (result i32)))
  (type (;5;) (func (param i64)))
  (type (;6;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 0)))
  (import "__" "update_available_memory" (func (;1;) (type 4)))
  (import "Mt" "call" (func (;2;) (type 2)))
  (import "Mt" "h" (func (;3;) (type 1)))
  (func (;4;) (type 1) (result i32)
    global.get 0
    i64.const 1
    i64.sub
    global.set 0
    global.get 0
    i64.const 0
    i64.lt_s
    if  ;; label = @1
      call 0
    end
    i32.const 5)
  (func (;5;) (type 2) (param i32) (result i32)
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
    local.get 0
    call 2)
  (func (;6;) (type 3) (param i32)
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
    local.get 0
    call_indirect (type 0))
  (func (;7;) (type 5) (param i64)
    local.get 0
    global.set 0)
  (func (;8;) (type 6) (result i64)
    global.get 0)
  (table (;0;) 5 5 funcref)
  (global (;0;) (mut i64) (i64.const 0))
  (export "Mt.call" (func 2))
  (export "call Mt.call" (func 5))
  (export "call" (func 6))
  (export "table" (table 0))
  (export "canister counter_set" (func 7))
  (export "canister counter_get" (func 8))
  (export "canister counter_instructions" (global 0))
  (elem (;0;) (i32.const 0) 4 4 4 3 2))
