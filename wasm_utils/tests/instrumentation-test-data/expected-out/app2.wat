(module
  (type (;0;) (func (param i64) (result i64)))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  (import "__" "update_available_memory" (func (;1;) (type 2)))
  (func (;2;) (type 0) (param i64) (result i64)
    (local i64)
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
    i64.const 3
    i64.mul
    call 4
    local.set 1
    block  ;; label = @1
      global.get 0
      i64.const 5
      i64.sub
      global.set 0
      local.get 1
      i64.const 1
      i64.and
      i32.wrap_i64
      br_if 0 (;@1;)
      global.get 0
      i64.const 7
      i64.sub
      global.set 0
      local.get 1
      i64.const 222
      i64.add
      local.set 1
      block  ;; label = @2
        global.get 0
        i64.const 5
        i64.sub
        global.set 0
        local.get 1
        i64.const 1
        i64.and
        i32.wrap_i64
        br_if 0 (;@2;)
        global.get 0
        i64.const 4
        i64.sub
        global.set 0
        local.get 1
        i64.const 1666
        i64.gt_s
        br_if 1 (;@1;)
        global.get 0
        i64.const 6
        i64.sub
        global.set 0
        local.get 1
        i64.const 100
        i64.mul
        local.tee 1
        i32.wrap_i64
        if  ;; label = @3
          global.get 0
          i64.const 4
          i64.sub
          global.set 0
          i64.const -1
          local.get 1
          i64.mul
          local.set 1
        else
          global.get 0
          i64.const 2
          i64.sub
          global.set 0
          local.get 0
          local.set 1
        end
      end
      local.get 1
      call 3
      local.set 1
    end
    local.get 1)
  (func (;3;) (type 0) (param i64) (result i64)
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
    i64.const 10
    local.get 0
    i64.mul)
  (func (;4;) (type 0) (param i64) (result i64)
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
    i64.const 1
    i64.add)
  (func (;5;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;6;) (type 4) (result i64)
    global.get 0)
  (global (;0;) (mut i64) (i64.const 0))
  (export "compute" (func 2))
  (export "tenfold" (func 3))
  (export "inc" (func 4))
  (export "canister counter_set" (func 5))
  (export "canister counter_get" (func 6))
  (export "canister counter_instructions" (global 0)))
