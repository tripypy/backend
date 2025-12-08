package com.ssafy.jjtrip.domain.trip.mapper;

import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

@MappedTypes(TripStatus.class)
public class TripStatusIdTypeHandler extends BaseTypeHandler<TripStatus> {

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, TripStatus parameter, JdbcType jdbcType) throws SQLException {
        ps.setLong(i, parameter.getId());
    }

    @Override
    public TripStatus getNullableResult(ResultSet rs, String columnName) throws SQLException {
        long id = rs.getLong(columnName);
        return rs.wasNull() ? null : fromId(id);
    }

    @Override
    public TripStatus getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        long id = rs.getLong(columnIndex);
        return rs.wasNull() ? null : fromId(id);
    }

    @Override
    public TripStatus getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        long id = cs.getLong(columnIndex);
        return cs.wasNull() ? null : fromId(id);
    }

    private TripStatus fromId(long id) {
        return Arrays.stream(TripStatus.values())
                .filter(e -> e.getId() == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Cannot convert " + id + " to TripStatus"));
    }
}
