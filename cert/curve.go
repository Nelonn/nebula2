package cert

type Curve int32

const (
	Curve_CURVE25519 Curve = 0
	Curve_P256       Curve = 1
)

func (x Curve) String() string {
	switch x {
	case Curve_CURVE25519:
		return "CURVE25519"
	case Curve_P256:
		return "P256"
	default:
		return "UNKNOWN"
	}
}
