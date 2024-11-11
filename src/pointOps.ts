const mcl = require('mcl-wasm')
import type { G1, Fp, Fp2 } from 'mcl-wasm'
import { g, neg, mul, add, sub, sqrt, sgn0, inv0, legendre } from './fieldOps'
import { hashToField } from './hashOps'
import { toHex } from './utils'
import { FIELD_ORDER, C2, C3, C4 } from './constants'

export function createFp2(a: string, b: string): Fp2 {
    const fp2_a: Fp = new mcl.Fp()
    const fp2_b: Fp = new mcl.Fp()
    fp2_a.setStr(a)
    fp2_b.setStr(b)
    const fp2: Fp2 = new mcl.Fp2()
    fp2.set_a(fp2_a)
    fp2.set_b(fp2_b)
    return fp2
}

export function hashToPoint(domain: Uint8Array, msg: Uint8Array): G1 {
    const hashRes = hashToField(domain, msg, 2)
    const e0 = hashRes[0]
    const e1 = hashRes[1]
    const p0 = mapToPoint(toHex(e0))
    const p1 = mapToPoint(toHex(e1))
    const p = mcl.add(p0, p1)
    p.normalize()
    return p
}

export function mapToPoint(eHex: `0x${string}`): G1 {
    const Z = 1n
    const fieldOrder = FIELD_ORDER

    const u = BigInt(eHex)

    let tv1 = mul(mul(u, u, fieldOrder), g(Z, fieldOrder), fieldOrder)
    const tv2 = add(1n, tv1, fieldOrder)
    tv1 = sub(1n, tv1, fieldOrder)
    const tv3 = inv0(mul(tv1, tv2, fieldOrder), fieldOrder)
    const tv5 = mul(mul(mul(u, tv1, fieldOrder), tv3, fieldOrder), C3, fieldOrder)
    const x1 = add(C2, neg(tv5, fieldOrder), fieldOrder)
    const x2 = add(C2, tv5, fieldOrder)
    const tv7 = mul(tv2, tv2, fieldOrder)
    const tv8 = mul(tv7, tv3, fieldOrder)
    const x3 = add(Z, mul(C4, mul(tv8, tv8, fieldOrder), fieldOrder), fieldOrder)

    let x
    let y
    if (legendre(g(x1, fieldOrder), fieldOrder) === 1n) {
        x = x1
        y = sqrt(g(x1, fieldOrder), fieldOrder)
    } else if (legendre(g(x2, fieldOrder), fieldOrder) === 1n) {
        x = x2
        y = sqrt(g(x2, fieldOrder), fieldOrder)
    } else {
        x = x3
        y = sqrt(g(x3, fieldOrder), fieldOrder)
    }
    if (sgn0(u) != sgn0(y)) {
        y = neg(y, fieldOrder)
    }

    const g1x: Fp = new mcl.Fp()
    const g1y: Fp = new mcl.Fp()
    const g1z: Fp = new mcl.Fp()
    g1x.setStr(x.toString(), 10)
    g1y.setStr(y.toString(), 10)
    g1z.setInt(1)
    const point: G1 = new mcl.G1()
    point.setX(g1x)
    point.setY(g1y)
    point.setZ(g1z)
    return point
}