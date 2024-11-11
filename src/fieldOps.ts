import { LEGENDRE_EXP, SQRT_EXP } from './constants'

export function mod(a: bigint, b: bigint) {
    return ((a % b) + b) % b
}

export function g(x: bigint, fieldOrder: bigint): bigint {
    return mod(mod(mod(x * x, fieldOrder) * x, fieldOrder) + 3n, fieldOrder)
}

export function neg(x: bigint, fieldOrder: bigint): bigint {
    return mod(-x, fieldOrder)
}

export function mul(a: bigint, b: bigint, fieldOrder: bigint): bigint {
    return mod(a * b, fieldOrder)
}

export function add(a: bigint, b: bigint, fieldOrder: bigint): bigint {
    return mod(a + b, fieldOrder)
}

export function sub(a: bigint, b: bigint, fieldOrder: bigint): bigint {
    return mod(a - b, fieldOrder)
}

export function exp(x: bigint, n: bigint, fieldOrder: bigint): bigint {
    let result = 1n
    let base = mod(x, fieldOrder)
    let e_prime = n
    while (e_prime > 0) {
        if (mod(e_prime, 2n) == 1n) {
            result = mod(result * base, fieldOrder)
        }
        e_prime = e_prime >> 1n
        base = mod(base * base, fieldOrder)
    }
    return result
}

export function sqrt(u: bigint, fieldOrder: bigint): bigint {
    return exp(u, SQRT_EXP, fieldOrder)
}

export function sgn0(x: bigint): bigint {
    return mod(x, 2n)
}

export function inv0(x: bigint, fieldOrder: bigint): bigint {
    if (x === 0n) {
        return 0n
    }
    return exp(x, fieldOrder - 2n, fieldOrder)
}

export function legendre(u: bigint, fieldOrder: bigint): 1n | 0n | -1n {
    const x = exp(u, LEGENDRE_EXP, fieldOrder)
    if (x === fieldOrder - 1n) {
        return -1n
    }
    if (x !== 0n && x !== 1n) {
        throw Error('Legendre symbol calc failed')
    }
    return x
}
