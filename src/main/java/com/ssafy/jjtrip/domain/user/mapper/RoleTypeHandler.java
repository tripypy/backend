package com.ssafy.jjtrip.domain.user.mapper;

import com.ssafy.jjtrip.domain.user.entity.Role;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@MappedTypes(Role.class)
public class RoleTypeHandler extends BaseTypeHandler<Role> {

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, Role parameter, JdbcType jdbcType) throws SQLException {
        ps.setLong(i, parameter.getId());
    }

    @Override
    public Role getNullableResult(ResultSet rs, String columnName) throws SQLException {
        Long id = rs.getLong(columnName);
        return rs.wasNull() ? null : Role.fromId(id);
    }

    @Override
    public Role getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        Long id = rs.getLong(columnIndex);
        return rs.wasNull() ? null : Role.fromId(id);
    }

    @Override
    public Role getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        Long id = cs.getLong(columnIndex);
        return cs.wasNull() ? null : Role.fromId(id);
    }
}
