package com.ssafy.jjtrip.domain.trip.mapper;

import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@MappedTypes(TripStatus.class)
public class TripStatusTypeHandler extends BaseTypeHandler<TripStatus> {

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, TripStatus parameter, JdbcType jdbcType) throws SQLException {
        ps.setString(i, parameter.name());
    }

    @Override
    public TripStatus getNullableResult(ResultSet rs, String columnName) throws SQLException {
        String name = rs.getString(columnName);
        return name == null ? null : TripStatus.valueOf(name);
    }

    @Override
    public TripStatus getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        String name = rs.getString(columnIndex);
        return name == null ? null : TripStatus.valueOf(name);
    }

    @Override
    public TripStatus getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        String name = cs.getString(columnIndex);
        return name == null ? null : TripStatus.valueOf(name);
    }
}
