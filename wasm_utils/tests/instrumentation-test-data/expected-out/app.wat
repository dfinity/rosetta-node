(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i64)))
  (type (;4;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 1)))
  (import "__" "update_available_memory" (func (;1;) (type 2)))
  (func (;2;) (type 0) (param i32) (result i32)
    (local i32 i32)
    global.get 0
    i64.const 513
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
    local.get 0
    local.get 0
    i32.mul
    i32.const 0
    local.get 0
    i32.sub
    local.get 0
    i32.const 666
    i32.gt_s
    select
    local.set 2
    block  ;; label = @1
      global.get 0
      i64.const 103
      i64.sub
      global.set 0
      local.get 0
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      loop  ;; label = @2
        global.get 0
        i64.const 313
        i64.sub
        global.set 0
        global.get 0
        i64.const 0
        i64.lt_s
        if  ;; label = @3
          call 0
        end
        local.get 1
        i32.const -1
        i32.xor
        i32.const 1
        i32.and
        local.get 2
        i32.add
        local.set 2
        local.get 0
        local.get 1
        loop  ;; label = @3
          global.get 0
          i64.const 404
          i64.sub
          global.set 0
          global.get 0
          i64.const 0
          i64.lt_s
          if  ;; label = @4
            call 0
          end
          i32.const 1
          drop
          i32.const 1
          drop
          i32.const 1
          drop
          i32.const 1
          drop
        end
        i32.const 1
        i32.add
        local.tee 1
        i32.ne
        br_if 0 (;@2;)
      end
    end
    local.get 2
    i32.const 97
    i32.mul
    i32.const 100
    i32.div_s)
  (func (;3;) (type 0) (param i32) (result i32)
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
    local.get 0
    i32.mul)
  (func (;4;) (type 3) (param i64)
    local.get 0
    global.set 0)
  (func (;5;) (type 4) (result i64)
    global.get 0)
  (memory (;0;) 17)
  (global (;0;) (mut i64) (i64.const 0))
  (export "memory" (memory 0))
  (export "compute" (func 2))
  (export "double" (func 3))
  (export "canister counter_set" (func 4))
  (export "canister counter_get" (func 5))
  (export "canister counter_instructions" (global 0)))
