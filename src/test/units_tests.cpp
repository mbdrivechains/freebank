// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The units DB and its view (gram-notes release, docs-local/GOLD_USD_SCOPE.md step 1): the overlay, the merged scan,
// one block's atomic write with its undo record and marker, and the undo that puts every key back.

#include <units.h>

#include <test/test_bitcoin.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

namespace {

UnitsKey K(uint32_t n) { return UnitsKey(UNITS_TEST).U32(n); }

uint32_t ValueOf(const CUnitsView& view, uint32_t n)
{
    uint32_t x = 0;
    BOOST_REQUIRE(view.Get(K(n), x));
    return x;
}

std::vector<uint32_t> ScanValues(const CUnitsView& view, const UnitsKey& start = UnitsKey(), size_t nMax = SIZE_MAX)
{
    std::vector<uint32_t> v;
    for (const std::pair<UnitsKey, UnitsValue>& p : view.Scan(UnitsKey(UNITS_TEST), start, nMax)) {
        CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
        uint32_t x;
        ss >> x;
        v.push_back(x);
    }
    return v;
}

bool WriteView(CUnitsDB& db, const CUnitsView& view, const uint256& hashBlock)
{
    std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
    view.GetChanges(mapChange, mapBefore);
    return db.WriteBlock(mapChange, mapBefore, hashBlock);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(units_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(units_key_order_is_field_order)
{
    // Big-endian fields: 256 sorts after 1 (a little-endian or varint key would put it first).
    BOOST_CHECK(K(1) < K(256));
    BOOST_CHECK(K(256) < K(65536));
    BOOST_CHECK(UnitsKey(UNITS_TEST).U32(7).U64(1) < UnitsKey(UNITS_TEST).U32(7).U64(1ULL << 40));
    BOOST_CHECK(K(7).HasPrefix(UnitsKey(UNITS_TEST)));
    BOOST_CHECK(!UnitsKey(UNITS_BEST_BLOCK).HasPrefix(UnitsKey(UNITS_TEST)));
}

BOOST_AUTO_TEST_CASE(units_view_overlay_and_scan)
{
    CUnitsDB db(1 << 20, true, true);   // in-memory
    {
        CUnitsView view(&db);
        for (uint32_t n : {1, 3, 5, 7})
            view.Put(K(n), n * 10);
        BOOST_REQUIRE(WriteView(db, view, uint256S("01")));
    }

    CUnitsView view(&db);
    BOOST_CHECK_EQUAL(ValueOf(view, 3), 30u);
    view.Put(K(3), (uint32_t)31);          // overwrite a stored key
    view.Erase(K(5));                      // erase a stored key
    view.Put(K(4), (uint32_t)40);          // a new key between stored ones
    view.Put(K(9), (uint32_t)90);          // a new key past the last stored one
    BOOST_CHECK_EQUAL(ValueOf(view, 3), 31u);
    BOOST_CHECK(!view.Have(K(5)));

    // The scan merges the DB with the view's writes, in key order.
    BOOST_CHECK((ScanValues(view) == std::vector<uint32_t>{10, 31, 40, 70, 90}));
    BOOST_CHECK((ScanValues(view, K(4)) == std::vector<uint32_t>{40, 70, 90}));
    BOOST_CHECK((ScanValues(view, UnitsKey(), 2) == std::vector<uint32_t>{10, 31}));

    // The DB itself is untouched until the view is written.
    BOOST_CHECK_EQUAL(db.Scan(UnitsKey(UNITS_TEST), UnitsKey(), SIZE_MAX).size(), 4u);

    // A view over no DB is an empty state.
    CUnitsView empty(nullptr);
    BOOST_CHECK(!empty.Have(K(1)));
    empty.Put(K(2), (uint32_t)20);
    BOOST_CHECK((ScanValues(empty) == std::vector<uint32_t>{20}));
}

BOOST_AUTO_TEST_CASE(units_block_write_and_undo)
{
    CUnitsDB db(1 << 20, true, true);
    const uint256 h1 = uint256S("01"), h2 = uint256S("02");
    {
        CUnitsView view(&db);
        view.Put(K(1), (uint32_t)10);
        view.Put(K(2), (uint32_t)20);
        BOOST_REQUIRE(WriteView(db, view, h1));
    }
    {
        CUnitsView view(&db);
        view.Put(K(1), (uint32_t)11);        // changed
        view.Erase(K(2));                    // erased
        view.Put(K(3), (uint32_t)30);        // created
        view.Put(K(4), (uint32_t)40);
        view.Erase(K(4));                    // created and erased in the same block: no change at all
        BOOST_REQUIRE(WriteView(db, view, h2));
    }
    uint256 hashBest;
    BOOST_CHECK(db.GetBestBlock(hashBest) && hashBest == h2);
    BOOST_CHECK(db.Exists(UnitsKey(UNITS_BLOCK_UNDO).Hash(h2)));

    // Undo block 2: every key back to block 1's value, the record gone, the marker at block 1.
    BOOST_REQUIRE(db.UndoBlock(h2, h1));
    CUnitsView after(&db);
    BOOST_CHECK_EQUAL(ValueOf(after, 1), 10u);
    BOOST_CHECK_EQUAL(ValueOf(after, 2), 20u);
    BOOST_CHECK(!after.Have(K(3)));
    BOOST_CHECK(!after.Have(K(4)));
    BOOST_CHECK(!db.Exists(UnitsKey(UNITS_BLOCK_UNDO).Hash(h2)));
    BOOST_CHECK(db.GetBestBlock(hashBest) && hashBest == h1);

    // Undo block 1 back to the empty state.
    BOOST_REQUIRE(db.UndoBlock(h1, uint256S("00")));
    BOOST_CHECK(db.Scan(UnitsKey(UNITS_TEST), UnitsKey(), SIZE_MAX).empty());
}

BOOST_AUTO_TEST_CASE(units_unchanged_block_writes_only_the_marker)
{
    CUnitsDB db(1 << 20, true, true);
    {
        CUnitsView view(&db);
        view.Put(K(1), (uint32_t)10);
        BOOST_REQUIRE(WriteView(db, view, uint256S("01")));
    }
    CUnitsView view(&db);
    view.Put(K(1), (uint32_t)10);            // written back to the same value
    std::map<UnitsKey, UnitsSlot> mapChange, mapBefore;
    view.GetChanges(mapChange, mapBefore);
    BOOST_CHECK(mapChange.empty());
    BOOST_REQUIRE(db.WriteBlock(mapChange, mapBefore, uint256S("02")));
    BOOST_CHECK(!db.Exists(UnitsKey(UNITS_BLOCK_UNDO).Hash(uint256S("02"))));
    // A block with no record undoes to just a marker step.
    BOOST_REQUIRE(db.UndoBlock(uint256S("02"), uint256S("01")));
    BOOST_CHECK_EQUAL(ValueOf(CUnitsView(&db), 1), 10u);
}

BOOST_AUTO_TEST_CASE(units_block_cannot_write_reserved_keys)
{
    CUnitsDB db(1 << 20, true, true);
    for (const UnitsKey& key : {UnitsKey(UNITS_BEST_BLOCK), UnitsKey(UNITS_BLOCK_UNDO).Hash(uint256S("01"))}) {
        CUnitsView view(&db);
        view.Put(key, (uint32_t)1);
        BOOST_CHECK(!WriteView(db, view, uint256S("05")));
    }
    uint256 hashBest;
    BOOST_CHECK(!db.GetBestBlock(hashBest));
}

BOOST_AUTO_TEST_CASE(units_block_undo_record_roundtrip)
{
    CUnitsBlockUndo undo;
    undo.vBefore.emplace_back(K(1), UnitsSlot(UnitsValue{1, 2, 3}));
    undo.vBefore.emplace_back(K(2), boost::none);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << undo;
    CUnitsBlockUndo back;
    ss >> back;
    BOOST_REQUIRE_EQUAL(back.vBefore.size(), 2u);
    BOOST_CHECK(back.vBefore[0].first == K(1) && back.vBefore[0].second && *back.vBefore[0].second == (UnitsValue{1, 2, 3}));
    BOOST_CHECK(back.vBefore[1].first == K(2) && !back.vBefore[1].second);
}

BOOST_AUTO_TEST_SUITE_END()
