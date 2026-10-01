package proxy

// Pipeline is the fixed, ordered addon chain, mirroring proxy/main.py's
// addons list exactly. The same ordered list is used for both the
// request and response phases; each phase only invokes addons that
// implement the corresponding interface, exactly like mitmproxy only
// calling the hook methods an addon actually defines.
type Pipeline struct {
	addons []Addon
}

// NewPipeline builds a Pipeline from an ordered addon list.
func NewPipeline(addons []Addon) *Pipeline {
	return &Pipeline{addons: addons}
}

// RunRequest runs every RequestAddon in pipeline order. Mirrors mitmproxy:
// even once fc.Response is set by an early addon (a block page, a
// redirect), every later addon's request hook still runs - only the
// actual upstream fetch is skipped. Addons that need to no-op once a
// response already exists check fc.URLAllowed/fc.MitmPassthrough
// themselves, exactly like their Python originals.
func (p *Pipeline) RunRequest(fc *FlowContext) {
	for _, a := range p.addons {
		if ra, ok := a.(RequestAddon); ok {
			ra.HandleRequest(fc)
		}
	}
}

// RunResponse runs every ResponseAddon in pipeline order.
func (p *Pipeline) RunResponse(fc *FlowContext) {
	for _, a := range p.addons {
		if ra, ok := a.(ResponseAddon); ok {
			ra.HandleResponse(fc)
		}
	}
}

// RunError runs every ErrorAddon in pipeline order (only RequestLogger
// implements this in practice, matching the Python original).
func (p *Pipeline) RunError(fc *FlowContext) {
	for _, a := range p.addons {
		if ea, ok := a.(ErrorAddon); ok {
			ea.HandleError(fc)
		}
	}
}

// ConnectGate returns the first addon in the pipeline implementing
// ConnectGate (ProxyAuthGate, in practice), or nil if none do.
func (p *Pipeline) ConnectGateAddon() ConnectGate {
	for _, a := range p.addons {
		if cg, ok := a.(ConnectGate); ok {
			return cg
		}
	}
	return nil
}

// SocksAuthGateAddon returns the first addon in the pipeline implementing
// SocksAuthGate (ProxyAuthGate, in practice), or nil if none do.
func (p *Pipeline) SocksAuthGateAddon() SocksAuthGate {
	for _, a := range p.addons {
		if sg, ok := a.(SocksAuthGate); ok {
			return sg
		}
	}
	return nil
}
