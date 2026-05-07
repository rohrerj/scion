package marketplace

import (
	"context"
	"crypto/x509"
	"fmt"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/storage"
	storageTrust "github.com/scionproto/scion/private/storage/trust"
	"github.com/scionproto/scion/private/trust"
)

type DB_Wrapper struct {
	db     storage.TrustDB
	client control_planeconnect.TrustMaterialServiceClient
}

func FromTrustDB(db storage.TrustDB, controlClient control_planeconnect.TrustMaterialServiceClient) *DB_Wrapper {
	return &DB_Wrapper{
		db:     db,
		client: controlClient,
	}
}

func (d *DB_Wrapper) requestTRCFromCS(ctx context.Context, isd uint32, base uint64, serial uint64) ([]byte, error) {
	rep, err := d.client.TRC(ctx, &connect.Request[control_plane.TRCRequest]{
		Msg: &control_plane.TRCRequest{
			Isd:    isd,
			Base:   base,
			Serial: serial,
		},
	})
	if err != nil {
		return nil, err
	}
	return rep.Msg.Trc, nil
}

func (d *DB_Wrapper) Chain(ctx context.Context, b []byte) ([]*x509.Certificate, error) {
	return d.db.Chain(ctx, b)
}

func (d *DB_Wrapper) Chains(ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {
	return d.db.Chains(ctx, q)
}

func (d *DB_Wrapper) Close() error {
	return d.db.Close()
}

func (d *DB_Wrapper) InsertChain(ctx context.Context, c []*x509.Certificate) (bool, error) {
	return d.db.InsertChain(ctx, c)
}

func (d *DB_Wrapper) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	return d.db.InsertTRC(ctx, trc)
}

func (d *DB_Wrapper) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	trc, err := d.db.SignedTRC(ctx, id)
	if err == nil && trc.IsZero() {
		return trc, nil
	}
	fmt.Println("trust material not found, must request from CS")
	raw, err := d.requestTRCFromCS(ctx, uint32(id.ISD), uint64(id.Base), uint64(id.Serial))
	if err != nil {
		return trc, err
	}
	trc, err = cppki.DecodeSignedTRC(raw)
	if err != nil {
		return trc, serrors.WrapNoStack("parsing TRC", err)
	}
	_, err = d.InsertTRC(ctx, trc)
	if err != nil {
		return trc, serrors.WrapNoStack("inserting TRC", err)
	}
	return trc, nil
}

func (d *DB_Wrapper) SignedTRCs(context.Context, storageTrust.TRCsQuery) (cppki.SignedTRCs, error) {
	panic("unimplemented")
}
