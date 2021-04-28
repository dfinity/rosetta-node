(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  (import "__" "update_available_memory" (func (;1;) (type 2)))
  (import "imports" "trace" (func (;2;) (type 0)))
  (func (;3;) (type 1)
    (local i32)
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
    i32.const 0
    local.set 0
    block  ;; label = @1
      loop  ;; label = @2
        global.get 0
        i64.const 4
        i64.sub
        global.set 0
        global.get 0
        i64.const 0
        i64.lt_s
        if  ;; label = @3
          call 0
        end
        local.get 0
        i32.const 10
        i32.eq
        br_if 1 (;@1;)
        global.get 0
        i64.const 7
        i64.sub
        global.set 0
        local.get 0
        call 2
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        br 0 (;@2;)
      end
    end)
  (func (;4;) (type 0) (param i32)
    (local i32)
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
    i32.const 0
    local.set 1
    loop  ;; label = @1
      global.get 0
      i64.const 10
      i64.sub
      global.set 0
      global.get 0
      i64.const 0
      i64.lt_s
      if  ;; label = @2
        call 0
      end
      local.get 1
      call 2
      local.get 1
      i32.const 1
      i32.add
      local.set 1
      local.get 0
      local.get 1
      i32.ne
      br_if 0 (;@1;)
    end)
  (func (;5;) (type 0) (param i32)
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
    i32.const 0
    i32.eq
    if  ;; label = @1
      global.get 0
      i64.const 2
      i64.sub
      global.set 0
      i32.const 3
      call 2
    else
      global.get 0
      i64.const 2
      i64.sub
      global.set 0
      i32.const 5
      call 2
    end)
  (func (;6;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;7;) (type 4) (result i64)
    global.get 0)
  (memory (;0;) 1)
  (global (;0;) (mut i64) (i64.const 0))
  (export "loop" (func 3))
  (export "countTo" (func 4))
  (export "if_then_else" (func 5))
  (export "memory" (memory 0))
  (export "canister counter_set" (func 6))
  (export "canister counter_get" (func 7))
  (export "canister counter_instructions" (global 0)))
