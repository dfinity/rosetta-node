(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  ;;
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  ;; System Api function to call after a `memory.grow`
  (import "__" "update_available_memory" (func (;1;) (type 2)))

  (func (;2;) (type 0) (param i32) (result i32)
    (local i32 i32 i32) ;; Last local used to cache the argument to `memory.grow`
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
    local.tee 3 ;; Save argument to `memory.grow`
    memory.grow
    local.get 3 ;; Load argument of `memory.grow`
    call 1 ;; Call `update_available_memory`
  )

  ;; Cycles counter setter and getter
  (func (;3;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;4;) (type 4) (result i64)
    global.get 0)

  (memory (;0;) 17 100)
  (global (;0;) (mut i64) (i64.const 0))
  (export "memory" (memory 0))
  (export "grow" (func 2))
  (export "canister counter_set" (func 3))
  (export "canister counter_get" (func 4))
  (export "canister counter_instructions" (global 0)))
