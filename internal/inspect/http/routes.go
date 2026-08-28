package http

import "github.com/HiggsNet/photon/internal/inspect"

// These aliases preserve the Observer JSON contract. Route semantics and
// construction belong to the canonical read model in internal/inspect.
type RoutesResponse = inspect.RoutesResponse
type RouteAssignment = inspect.RouteAssignment
type AuthorizedRoute = inspect.AuthorizedRoute
type IPAMPool = inspect.IPAMPool
type IPAMAssignment = inspect.IPAMAssignment
type RouteAuthorizationError = inspect.RouteAuthorizationError
type BirdRoutesView = inspect.BirdRoutesView
type BirdRouteView = inspect.BirdRouteView

var RoutesFromAuthorizedSet = inspect.RoutesFromAuthorizedSet
var BuildBirdRouteViews = inspect.BuildBirdRouteViews
