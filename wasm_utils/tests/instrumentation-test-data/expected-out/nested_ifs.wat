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
    i64.const 6
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
    i64.and
    i32.wrap_i64
    if  ;; label = @1
      global.get 0
      i64.const 7
      i64.sub
      global.set 0
      local.get 0
      i64.const -1
      i64.mul
      local.tee 0
      i64.const -50
      i64.lt_s
      if  ;; label = @2
        global.get 0
        i64.const 4
        i64.sub
        global.set 0
        local.get 0
        i64.const 100
        i64.mul
        local.set 0
      else
        global.get 0
        i64.const 6
        i64.sub
        global.set 0
        local.get 0
        i64.const -111
        i64.add
        local.set 0
        local.get 0
        local.set 0
      end
    else
      global.get 0
      i64.const 9
      i64.sub
      global.set 0
      local.get 0
      i64.const 1
      i64.add
      i64.const 2
      i64.mul
      local.tee 0
      i64.const 50
      i64.lt_s
      if  ;; label = @2
        global.get 0
        i64.const 4
        i64.sub
        global.set 0
        local.get 0
        i64.const 100
        i64.mul
        local.set 0
      else
        global.get 0
        i64.const 6
        i64.sub
        global.set 0
        local.get 0
        i64.const 111
        i64.add
        local.set 0
        local.get 0
        local.set 0
      end
    end
    local.get 0)
  (func (;3;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;4;) (type 4) (result i64)
    global.get 0)
  (global (;0;) (mut i64) (i64.const 0))
  (export "compute" (func 2))
  (export "canister counter_set" (func 3))
  (export "canister counter_get" (func 4))
  (export "canister counter_instructions" (global 0)))
