package io.github.wushilin.pfrelay;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** A client's live connections and its totals: local bookkeeping only. */
final class Registry {
    /** The bookkeeping of one connection. */
    static final class Record {
        final String id;
        final Side side;
        final Instant opened = Instant.now();
        final AtomicLong sent = new AtomicLong();
        final AtomicLong received = new AtomicLong();
        final AtomicBoolean finished = new AtomicBoolean();
        Conn conn;

        Record(String id, Side side) {
            this.id = id;
            this.side = side;
        }

        ConnInfo info() {
            return new ConnInfo(id, side, opened, sent.get(), received.get(),
                    conn != null && conn.wroteEof(), conn != null && conn.readEof());
        }
    }

    private final Set<Record> live = new LinkedHashSet<>();
    private long opened;
    private long failed;
    private long sent; // of the connections that have ended
    private long received;

    synchronized Record add(String id, Side side) {
        Record r = new Record(id, side);
        live.add(r);
        opened++;
        return r;
    }

    /** Moves r out of the live set, once. */
    void finish(Record r, boolean didFail) {
        if (!r.finished.compareAndSet(false, true)) {
            return;
        }
        synchronized (this) {
            live.remove(r);
            if (didFail) {
                failed++;
            }
            sent += r.sent.get();
            received += r.received.get();
        }
    }

    synchronized Stats stats() {
        long s = sent, rcv = received;
        for (Record r : live) {
            s += r.sent.get();
            rcv += r.received.get();
        }
        return new Stats(opened, live.size(), failed, s, rcv);
    }

    List<ConnInfo> conns() {
        List<Record> rs;
        synchronized (this) {
            rs = new ArrayList<>(live);
        }
        List<ConnInfo> out = new ArrayList<>(rs.size());
        for (Record r : rs) {
            out.add(r.info());
        }
        out.sort(Comparator.comparing(ConnInfo::opened));
        return out;
    }
}
