/*
Copyright 2021 The Vitess Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by Sizegen. DO NOT EDIT.

package evalengine

import hack "vitess.io/vitess/go/hack"

type cachedObject interface {
	CachedSize(alloc bool) int64
}

func (cached *BinaryExpr) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(48)
	}
	// field Op vitess.io/vitess/go/vt/vtgate/evalengine.BinaryOp
	if cc, ok := cached.Op.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	// field Left vitess.io/vitess/go/vt/vtgate/evalengine.Expr
	if cc, ok := cached.Left.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	// field Right vitess.io/vitess/go/vt/vtgate/evalengine.Expr
	if cc, ok := cached.Right.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	return size
}
func (cached *BindVariable) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(16)
	}
	// field Key string
	size += hack.RuntimeAllocSize(int64(len(cached.Key)))
	return size
}
func (cached *Column) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(8)
	}
	return size
}
func (cached *ComparisonExpr) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(48)
	}
	// field Op vitess.io/vitess/go/vt/vtgate/evalengine.ComparisonOp
	if cc, ok := cached.Op.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	// field Left vitess.io/vitess/go/vt/vtgate/evalengine.Expr
	if cc, ok := cached.Left.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	// field Right vitess.io/vitess/go/vt/vtgate/evalengine.Expr
	if cc, ok := cached.Right.(cachedObject); ok {
		size += cc.CachedSize(true)
	}
	return size
}
func (cached *EvalResult) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(64)
	}
	// field bytes []byte
	size += hack.RuntimeAllocSize(int64(cap(cached.bytes)))
	return size
}
func (cached *Literal) CachedSize(alloc bool) int64 {
	if cached == nil {
		return int64(0)
	}
	size := int64(0)
	if alloc {
		size += int64(64)
	}
	// field Val vitess.io/vitess/go/vt/vtgate/evalengine.EvalResult
	size += cached.Val.CachedSize(false)
	return size
}
